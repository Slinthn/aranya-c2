use std::{
    sync::Arc,
    net::SocketAddr,
    collections::BTreeMap,
    time::Duration,
    vec::Vec
};
use aranya_crypto::Rng as AranyaRng;
use aranya_runtime::{
    Address, COMMAND_RESPONSE_MAX, Command, GraphId, MAX_SYNC_MESSAGE_SIZE, PeerCache, Prior, Sink, Storage, StorageProvider, SyncCommand, SyncRequestMessage, SyncRequester, SyncResponder, SyncType, TraversalBuffers, VmEffect
};
use bytes::{Bytes, BytesMut};
use heapless::Vec as HeaplessVec;
use s2n_quic::{Client as QuicClient, Connection, Server, client::Connect, provider::limits::Limits};
use tokio::{sync::Mutex, time::sleep};
use rand::{
    Rng,
    prelude::*
};

use crate::{config::{self, C2ClientState}};

// Shorthand for Arc Mutex just to aid readability
pub type AM<T> = Arc<Mutex<T>>;

pub struct C2Syncer<S: Sink<VmEffect>> {
    pub clientstate: C2ClientState,
    pub sink: S,
    pub connections: Vec<SocketAddr>,
    pub buffers: TraversalBuffers,
    pub remote_heads: BTreeMap<SocketAddr, PeerCache>
}

impl<S: Sink<VmEffect>> C2Syncer<S> {
    pub fn new(clientstate: C2ClientState, sink: S) -> Self {
        Self {
            clientstate,
            sink,
            connections: Vec::new(),
            buffers: TraversalBuffers::new(),
            remote_heads: BTreeMap::new()
        }
    }
}

fn update_commands<S: Sink<VmEffect>>(
    syncer: &mut C2Syncer<S>,
    commands: &HeaplessVec<SyncCommand<'_>, COMMAND_RESPONSE_MAX>,
    remote_addr: SocketAddr,
    graph: GraphId
) -> usize {
    let aranya = &mut syncer.clientstate;
    let sink = &mut syncer.sink;
    let primary = &mut syncer.buffers.primary;

    let mut tx = aranya.transaction(graph);
    let count = aranya.add_commands(&mut tx, sink, commands, primary);
    let _ = aranya.commit(tx, sink, primary);
    let _ = aranya.update_heads(
        graph,
        commands.iter().filter_map(|cmd| cmd.address().ok()),
        syncer.remote_heads.entry(remote_addr).or_default(),
        primary
    );

    match count {
        Ok(c) => c,
        Err(_) => 0
    }
}

async fn handle_request<S: Sink<VmEffect>>(
    mut conn: Connection,
    // TODO: Remove quic ?? - probably not, need it for syncing
    quic: Arc<QuicClient>,
    syncerm: AM<C2Syncer<S>>,
) {
    // println!("I am handling this shit");
    conn.keep_alive(true);
    let stream = conn.accept_bidirectional_stream().await;
    if let Ok(Some(mut s)) = stream {
        let (mut receive_stream, mut send_stream) = s.split();
        // println!("The stream is here :)");
        let addr = match receive_stream.connection().remote_addr() {
            Ok(mut addr) => {
                addr.set_port(addr.port() + 1);
                
                // Add this connection to the connections list
                let mut syncer = syncerm.lock().await;

                if !syncer.connections.contains(&addr) {
                    syncer.connections.push(addr);
                }

                addr
            },
            Err(_) => {
                println!("Failed to get peer address");
                return;
            }
        };
        // println!("About to get the request receive thing");

        let mut req = Vec::new();

        println!("RECEIVING");
        while let Ok(Some(r)) = receive_stream.receive().await {
            // println!("RECEIVED SOME DATA");
            req.extend_from_slice(&r);
        }
        // println!("DONE RECEIVING");

        // println!("{}", req.len());

        println!("I got it");
        let (peers, remaining) = match postcard::take_from_bytes::<Vec<SocketAddr>>(&req) {
            Ok((peers, remaining)) => (peers, remaining),
            Err(e) => {
                println!("Error parsing peers");
                println!("{e}");
                return;
            }
        };

        // Get connections from peer and add them to our list
        {
            let mut syncer = syncerm.lock().await;
            for peer in peers {
                if !syncer.connections.contains(&peer) {
                    syncer.connections.push(peer);
                }
            }
        }

        // Loop for all the commands until failure
        // loop {
            // println!("RECEIVING2");

            // println!("RECEIVING3");

            // println!("RECEIVING LEN: {}", remaining.len());

            let (sync_type, remaining) = match postcard::take_from_bytes::<SyncType>(remaining) {
                Ok((sync_type, remaining)) => (sync_type, remaining),
                Err(e) => {
                    println!("Error parsing sync data");
                    println!("{}", e);
                    return;
                }
            };

            // remaining = r;

            // println!("{sync_type:?}");

            if let SyncType::Poll { request } = sync_type {
                // println!("RECEIVED SYNC MESSAGE");
                let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

                let mut responder = SyncResponder::new();
                // TODO: Error handling ??
                let _ = responder.receive(request);

                let syncaddrs = {
                    let syncer = syncerm.lock().await;
                    syncer.connections.to_vec()
                };

                {
                    let syncer = &mut *syncerm.lock().await;
                    let tbuffers = &mut syncer.buffers;
                    let cache = syncer.remote_heads.entry(addr).or_default();

                    let _ = responder.poll(
                        &mut buffer,
                        syncer.clientstate.provider(),
                        cache,
                        tbuffers
                    );
                }

                let mut bytes = [Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), buffer.into()];

                println!("0:{}", bytes[0].len());
                println!("1:{}", bytes[1].len());

                let mut stream = match conn.open_bidirectional_stream().await {
                    Ok(v) => v,
                    Err(e) => {
                        println!("BIG ERROR {e}");
                        return;
                    }
                };
                if let Err(e) = stream.send_vectored(&mut bytes).await {
                    println!("FAILED TO SEND STUFF! {e}");
                }
                stream.finish();
                // tokio::time::sleep(tokio::time::Duration::from_millis(10000));
                println!("SENT THE STUFF!");
            } else if let SyncType::Push { message, graph_id } = sync_type {
                let prevhead = {
                    let mut syncer = syncerm.lock().await;
                    syncer.clientstate.head_address(graph_id).ok()
                };
                
                let mut requester = SyncRequester::new_session_id(graph_id, message.session_id());
                // println!("AAAA");
                if let Ok(Some(commands)) = requester.get_sync_commands(message, remaining) && commands.len() > 0 {
                    println!("RECEIVING {} COMMANDS", commands.len());
                    let count = {
                        let mut syncer = syncerm.lock().await;
                        // println!("UPDATING COMMANDS");
                        update_commands(
                            &mut *syncer,
                            &commands,
                            addr,
                            graph_id
                        )
                    };

                    // TODO: What if invalid commands ? don't do this next part then
                    // Sync with everyone else with regard to
                    //   this/these new command(s)
                    if count > 0 {
                        let syncaddrs: Vec<SocketAddr> = {
                            let syncer = syncerm.lock().await;
                            syncer.connections.to_vec()
                        };
                        
                        let mut syncer = syncerm.lock().await;
                        for syncaddr in syncaddrs {
                            c2push_sync(
                                syncaddr,
                                Arc::clone(&quic),
                                &mut syncer.clientstate,
                                graph_id,
                                prevhead
                            );

                            sleep(Duration::from_millis(10)).await;
                        }
                    } else {
                        return;
                    }
                }
            }
        // }
    }
    // conn.close(0u32.into());
}

pub fn new_quic_client(source_addr: SocketAddr) -> QuicClient {
    // TODO: Fix unwrap crap
    QuicClient::builder()
        .with_limits(Limits::new()
            .with_max_handshake_duration(Duration::from_secs(5)).unwrap()
            .with_max_idle_timeout(Duration::from_secs(5)).unwrap()
        ).unwrap()
        .with_tls(config::CERTIFICATE)
        .unwrap()
        .with_io(source_addr)
        .unwrap()
        .start()
        .unwrap()
}

pub async fn c2sync<S: Sink<VmEffect>>(
    remote_addr: SocketAddr,
    client: Arc<QuicClient>,
    syncerm: AM<C2Syncer<S>>,
    graph: GraphId
) {

    // TODO: Is with_server_name required here ?
    let conn = client
        .connect(Connect::new(remote_addr).with_server_name("localhost"))
        .await;

    if let Ok(mut c) = conn {
        // c.keep_alive(true);
        c.keep_alive(true);
        let stream = c.open_bidirectional_stream().await;
        
        if let Ok(mut s) = stream {
            let (mut receive_stream, mut send_stream) = s.split();
            let mut requester = SyncRequester::new(graph, AranyaRng);
            
            let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
            
            let syncaddrs = {
                let syncerl = syncerm.lock().await;
                syncerl.connections.to_vec()
            };

            let (len, _) = {
                let syncer = &mut *syncerm.lock().await;
                let tbuffers = &mut syncer.buffers;

                let cache = syncer.remote_heads.entry(remote_addr).or_default();

                requester.poll(
                    &mut buffer,
                    syncer.clientstate.provider(),
                    cache,
                    &mut tbuffers.primary,
                ).unwrap()
            };

            buffer.truncate(len);
            buffer.shrink_to_fit();

            println!("SENDING VECTORED");
            if let Err(e) = send_stream.send_vectored(&mut [Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), buffer.into()]).await {
                println!("COULD NOT SEND DATA {e}");
                return;
            }
            send_stream.finish();

            let mut stream = match c.accept_bidirectional_stream().await {
                Ok(Some(v)) => {
                    v
                },
                Ok(None) => {return;},
                Err(e) => {
                    println!("Couldn't make stream lol {e}");
                    return;
                }
            };

            println!("SENDING VECTORED DONE");

            // let mut recv: HeaplessVec<u8, MAX_SYNC_MESSAGE_SIZE> = HeaplessVec::new();
            let mut recv = Vec::new();

            while let Ok(Some(data)) = stream.receive().await {
                // println!("RECEIVED DATA FROM SERVER :)))))");
                let _ = recv.extend_from_slice(&data);
            }

            println!("too late");

            let (peers, remaining) = match postcard::take_from_bytes::<Vec<SocketAddr>>(recv.as_slice()) {
                Ok((peers, remaining)) => (peers, remaining),
                Err(e) => {
                    println!("Error parsing peers 2");
                    println!("{e}");
                    println!("LEN: {}", recv.len());
                    return;
                }
            };

            {
                let mut syncer = syncerm.lock().await;
                for peer in peers {
                    if !syncer.connections.contains(&peer) {
                        syncer.connections.push(peer);
                    }
                }
            }

            if let Ok(Some(recvdata)) = requester.receive(&remaining) {
                let mut syncer = syncerm.lock().await;
                println!("Updating the commands now");
                update_commands(
                    &mut *syncer,
                    &recvdata,
                    remote_addr,
                    graph
                );
            } else {
                println!("Error receiving commands sync");
            }
        }
        // c.close(0u32.into());
    }
}

pub async fn c2push<S: Sink<VmEffect>>(
    remote_addr: SocketAddr,
    client: Arc<QuicClient>,
    syncerm: AM<C2Syncer<S>>,
    graph: GraphId
) {
    let mut responder = SyncResponder::new();
    let mut commands = HeaplessVec::new();

    // Random session ID
    let mut dst = [0u8; 16];
    rand::rng().fill_bytes(&mut dst);
    let session_id = u128::from_le_bytes(dst);

    {
        let mut syncerl = syncerm.lock().await;
        let cache = syncerl.remote_heads.entry(remote_addr).or_default();
        match commands.extend_from_slice(cache.heads()) {
            Ok(()) => {},
            Err(e) => eprintln!("extend_from_slice error: {e:?}")
        }
    }

    let _ = responder.receive(SyncRequestMessage::SyncRequest {
        session_id,
        graph_id: graph,
        max_bytes: 0,
        commands,
    });

    let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

    let syncaddrs: Vec<SocketAddr> = {
        let syncer = syncerm.lock().await;
        syncer.connections.to_vec()
    };

    {
        let syncer = &mut *syncerm.lock().await;
        let tbuffers = &mut syncer.buffers;
        match responder.push(
            &mut buffer,
            syncer.clientstate.provider(),
            tbuffers
        ) {
            Ok(len) => {
                // println!("I am about to send my mfing data");
                // println!("LENGTH: {len}");
                buffer.truncate(len);
                // buffer.shrink_to_fit();

                if len > 0 {
                    let conn = client
                        .connect(Connect::new(remote_addr).with_server_name("localhost"))
                        .await;

                    if let Ok(mut c) = conn {
                        let _ = c.keep_alive(true);
                        let stream = c.open_bidirectional_stream().await;
                        if let Ok(mut s) = stream {
                            // TODO: syncer is locked here, but its okay because UDP ?
                            match s.send_vectored(&mut [
                                Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()),
                                buffer.into()
                            ]).await {
                                Ok(()) => {},
                                Err(e) => eprintln!("send_vectored: {}", e)
                            };
                        }
                    }
                }
            },
            Err(e) => {
                println!("Error sending c2push data");
                println!("{graph}");
                println!("{e:?}");
            }
        }
    }
}

// Almost replica of c2push but for the operator because of
//   the way the code is written, it's not possible to make a
//   C2Syncer and pass in the clientstate... otherwise all my
//   functions will become async and everything will be await
//   and locks everywhere :(
pub fn c2push_sync(
    remote_addr: SocketAddr,
    client: Arc<QuicClient>,
    clientstate: &mut C2ClientState,
    graph: GraphId,
    // Optional parameter for where to start
    head: Option<Address>
) {
    let mut commands = HeaplessVec::new();
    
    if let Some(head) = head {
        commands.push(head);
    }

    // Random session ID
    let mut dst = [0u8; 16];
    rand::rng().fill_bytes(&mut dst);
    let session_id = u128::from_le_bytes(dst);

    let mut allbuffers = Vec::new();
    // Lets push the entire thing, but we need to keep looping to make srue
    //   that we push the entire thing, since our commands array is empty
    loop {
        let mut responder = SyncResponder::new();
        let _ = responder.receive(SyncRequestMessage::SyncRequest {
            session_id,
            graph_id: graph,
            max_bytes: 0,
            commands: commands.clone(),
        });

        let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

        let mut tbuffers = TraversalBuffers::new();
        match responder.push(
            &mut buffer,
            clientstate.provider(),
            &mut tbuffers
        ) {
            Ok(len) => {
                // NOTE: This is a bit of a hack because I now need to retrieve
                //   the commands that were just written to the buffer so that
                //   I can tell Aranya the rest of the comamnds to push
                let (syncmsg, remaining) = match postcard::take_from_bytes::<SyncType>(&buffer) {
                    Ok((sync_type, remaining)) => (sync_type, remaining),
                    Err(e) => {
                        // println!("NOTHING TO SYNC 3");
                        break;
                    }
                };

                let SyncType::Push { message, graph_id } = syncmsg else {
                    // println!("NOTHING TO SYNC 2");
                    break;
                };

                let mut requester = SyncRequester::new_session_id(graph_id, message.session_id());

                match requester.get_sync_commands(message, remaining) {
                    Ok(Some(mut synccommands)) => {
                        // println!("SYNC {}", synccommands.len());
                        for command in synccommands {
                            commands = HeaplessVec::new();
                            commands.push(command.address()
                            .expect("Could not get cmd address"));
                        }
                    },
                    _ => {
                        // println!("Nothing");
                        break;
                    },
                    Err(e) => {
                        // println!("FAILED");
                        // println!("{e}");
                        break;
                    }
                }


                if len > 0 {
                    // buffer.truncate(len);
                    allbuffers.push(buffer);
                } else {
                    break;
                }
            },
            Err(e) => {
                println!("Error sending c2push data");
                println!("{graph}");
                println!("{e:?}");
                break;
            }
        }
    }

    tokio::spawn(async move {
        let conn = client
            .connect(Connect::new(remote_addr).with_server_name("localhost"))
            .await;

        // println!("LEN: {}", allbuffers.len());

        if let Ok(mut c) = conn {
            let _ = c.keep_alive(true);
            let stream = c.open_bidirectional_stream().await;
            if let Ok(mut s) = stream {
                let emptyvec: Vec<SocketAddr> = Vec::new();
                let mut finaldata = BytesMut::new();
                finaldata.extend_from_slice(
                    &Bytes::from(postcard::to_allocvec(&emptyvec).unwrap())
                );

                for buffer in allbuffers {
                    // println!("{}", buffer.len());
                    finaldata.extend_from_slice(&buffer);
                }

                match s.send(finaldata.freeze()).await {
                    Ok(()) => {},
                    Err(e) => eprintln!("send_vectored: {}", e)
                };
            }
        }
    });
}

pub async fn run_c2syncer<S: Sink<VmEffect> + Send + 'static>(
    syncer: AM<C2Syncer<S>>,
    client: Arc<QuicClient>,
    bind: SocketAddr
) {
    let Ok(mut server) = Server::builder()
        .with_tls((config::CERTIFICATE, config::KEY))
        .unwrap()
        .with_io(bind)
        .unwrap()
        .start() else {
        print!("Failed to start server");
        return;
    };

    loop {
        match server.accept().await {
            Some(conn) => {
                let syncerc = Arc::clone(&syncer);
                let clientc = Arc::clone(&client);

                tokio::spawn(async move {
                    handle_request(conn, clientc, syncerc).await;
                });
            },
            None => {}
        }
    }
}
