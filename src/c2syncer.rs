use std::{
    sync::Arc,
    net::SocketAddr,
    collections::BTreeMap,
    time::Duration,
    vec::Vec
};
use aranya_crypto::Rng;
use aranya_runtime::{
    COMMAND_RESPONSE_MAX, Command, GraphId, MAX_SYNC_MESSAGE_SIZE, PeerCache, Sink, SyncCommand, SyncRequestMessage, SyncRequester, SyncResponder, SyncType, TraversalBuffers, VmEffect
};
use bytes::Bytes;
use heapless::Vec as HeaplessVec;
use s2n_quic::{Client as QuicClient, Connection, Server, client::Connect, provider::limits::Limits};
use tokio::{sync::Mutex, time::sleep};

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

async fn update_commands<S: Sink<VmEffect>>(
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
    let stream = conn.accept_bidirectional_stream().await;
    if let Ok(Some(mut s)) = stream {
        // println!("The stream is here :)");
        let addr = match s.connection().remote_addr() {
            Ok(mut addr) => {
                addr.set_port(config::PORT);
                
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

        if let Ok(Some(req)) = s.receive().await {
        // println!("I got it");
            let (peers, remaining) = match postcard::take_from_bytes::<Vec<SocketAddr>>(&req) {
                Ok((peers, remaining)) => (peers, remaining),
                Err(_) => {
                    println!("Error parsing peers");
                    return;
                }
            };
            // println!("RECEIVING2");

            // Get connections from peer and add them to our list
            {
                let mut syncer = syncerm.lock().await;
                for peer in peers {
                    if !syncer.connections.contains(&peer) {
                        syncer.connections.push(peer);
                    }
                }
            }

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

            // println!("{sync_type:?}");

            if let SyncType::Poll { request } = sync_type {
                let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

                let mut responder = SyncResponder::new();
                // TODO: Error handling ??
                let _ = responder.receive(request);

                // let syncaddrs = {
                //     let syncer = syncerm.lock().await;
                //     syncer.connections.to_vec()
                // };

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

                let _ = s.send_vectored(&mut [/* Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), */ buffer.into()]).await;
            } else if let SyncType::Push { message, graph_id } = sync_type {
                let mut requester = SyncRequester::new_session_id(graph_id, message.session_id());
                // println!("AAAA");
                if let Ok(Some(commands)) = requester.get_sync_commands(message, remaining) && commands.len() > 0 {
                    let count = {
                        let mut syncer = syncerm.lock().await;
                        // println!("UPDATING COMMANDS");
                        update_commands(
                            &mut *syncer,
                            &commands,
                            addr,
                            graph_id
                        ).await
                    };

                    // TODO: What if invalid commands ? don't do this next part then
                    // Sync with everyone else with regard to
                    //   this/these new command(s)
                    if count > 0 {
                        let syncaddrs: Vec<SocketAddr> = {
                            let syncer = syncerm.lock().await;
                            syncer.connections.to_vec()
                        };

                        for mut syncaddr in syncaddrs {
                            syncaddr.set_port(config::PORT);
                            c2push(
                                syncaddr,
                                Arc::clone(&quic),
                                Arc::clone(&syncerm),
                                graph_id
                            ).await;

                            sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            }
        }
    }
    conn.close(0u32.into());
}

pub fn new_quic_client(source_addr: SocketAddr) -> QuicClient {
    // TODO: Fix unwrap crap
    QuicClient::builder()
        .with_limits(Limits::new()
            .with_max_handshake_duration(Duration::from_secs(1)).unwrap()
            .with_max_idle_timeout(Duration::from_secs(1)).unwrap()
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
        let stream = c.open_bidirectional_stream().await;

        if let Ok(mut s) = stream {
            let mut requester = SyncRequester::new(graph, Rng);
            
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

            let _ = s.send_vectored(&mut [Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), buffer.into()]).await;

            let mut recv: HeaplessVec<u8, MAX_SYNC_MESSAGE_SIZE> = HeaplessVec::new();

            while let Ok(Some(data)) = s.receive().await {
                let _ = recv.extend_from_slice(&data);
            }

            if let Ok(Some(recvdata)) = requester.receive(&recv) {
                let mut syncer = syncerm.lock().await;
                update_commands(
                    &mut *syncer,
                    &recvdata,
                    remote_addr,
                    graph
                ).await;
            }
        }
        c.close(0u32.into());
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
    use rand::prelude::*;
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
                                Err(e) => eprintln!("send_vecotred: {}", e)
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

pub async fn run_c2syncer<S: Sink<VmEffect> + Send + 'static>(
    syncer: C2Syncer<S>,
    client: QuicClient,
    bind: SocketAddr
) {
    let mut server = match Server::builder()
        .with_tls((config::CERTIFICATE, config::KEY))
        .unwrap()
        .with_io(bind)
        .unwrap()
        .start()
    {
        Ok(v) => v,
        Err(e) => {
            print!("Failed to start server:\n{:?}\n", e);
            return;
        }
    };

    // for host in syncer.connections {
    //     c2push();
    // }

    let syncera = Arc::new(Mutex::new(syncer));
    let clienta = Arc::new(client);

    loop {
        match server.accept().await {
            Some(conn) => {
                let syncerc = Arc::clone(&syncera);
                let clientc = Arc::clone(&clienta);

                tokio::spawn(async move {
                    handle_request(conn, clientc, syncerc).await;
                });
            },
            None => {}
        }
    }
}
