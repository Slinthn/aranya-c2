use std::{
    sync::Arc,
    net::SocketAddr,
    collections::BTreeMap,
    time::Duration
};
use aranya_crypto::Rng;
use aranya_runtime::{
    Command, GraphId, MAX_SYNC_MESSAGE_SIZE, PeerCache, Sink, Storage, StorageProvider, SyncRequestMessage, SyncRequester, SyncResponder, SyncType, TraversalBuffers, VmEffect
};
use bytes::Bytes;
use heapless::Vec;
use rand::seq::IndexedRandom;
use s2n_quic::{Client, Connection, Server, client::Connect, provider::limits::Limits};
use tokio::time::sleep;

use crate::{common::AM, config::{self, C2ClientState}};

pub struct C2Syncer<S: Sink<VmEffect>> {
    pub client: AM<C2ClientState>,
    pub sink: AM<S>,
    pub connections: std::vec::Vec<SocketAddr>,
    pub buffers: TraversalBuffers,
    pub remote_heads: BTreeMap<SocketAddr, PeerCache>
}

async fn handle_request<S: Sink<VmEffect>>(
    mut conn: Connection,
    // TODO: Remove client ??
    client: Arc<Client>,
    syncerm: AM<C2Syncer<S>>,
) {
    // println!("I am handling this shit");
    let stream = conn.accept_bidirectional_stream().await;
    if let Ok(Some(mut s)) = stream {
        // println!("The stream is here :)");
        let addr = match s.connection().remote_addr() {
            Ok(mut addr) => {
                addr.set_port(config::PORT);
                
                // Add to connections list
                let mut syncerl = syncerm.lock().await;

                if !syncerl.connections.contains(&addr) {
                    syncerl.connections.push(addr);
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
            let (peers, remaining) = match postcard::take_from_bytes::<std::vec::Vec<SocketAddr>>(&req) {
                Ok((peers, remaining)) => (peers, remaining),
                Err(_) => {
                    println!("Error parsing peers");
                    return;
                }
            };
        // println!("RECEIVING2");
        

            {
                let mut syncerl = syncerm.lock().await;
                for peer in peers {
                    if !syncerl.connections.contains(&peer) {
                        syncerl.connections.push(peer);
                    }
                }
            }

        // println!("RECEIVING3");

        println!("RECEIVING LEN: {}", remaining.len());

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
                    let mut clientc = syncer.client.lock().await;
                    let tbuffers = &mut syncer.buffers;
                    let cache = syncer.remote_heads.entry(addr).or_default();

                    responder.poll(&mut buffer, clientc.provider(), cache, tbuffers);
                }

                s.send_vectored(&mut [/* Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), */ buffer.into()]).await;
            } else if let SyncType::Push { message, graph_id } = sync_type {
                let mut requester = SyncRequester::new_session_id(graph_id, message.session_id());
                // println!("AAAA");
                if let Ok(Some(cmds)) = requester.get_sync_commands(message, remaining) && cmds.len() > 0 {
                    let count = {
                        let syncer = &mut *syncerm.lock().await;
                        let mut clientc = syncer.client.lock().await;
                        let mut sinkc = syncer.sink.lock().await;
                        let tbuffers = &mut syncer.buffers;

                        let cache = syncer.remote_heads.entry(addr).or_default();

                        let mut tx = clientc.transaction(graph_id);
                        let count = clientc.add_commands(&mut tx, &mut *sinkc, &cmds, &mut tbuffers.primary);

                        if count.is_ok() {
                            clientc.commit(tx, &mut *sinkc, &mut tbuffers.primary);
                            if clientc.update_heads(
                                graph_id,
                                cmds.iter().filter_map(|cmd| cmd.address().ok()),
                                cache,
                                &mut tbuffers.primary,
                            ).is_err()
                            {
                                println!("ERROR UPDATING HEADS");
                            }
                        }


                        count
                    };

                    // Sync with everyone else with regard to
                    //   this/these new command(s)
                    if let Ok(cu) = count && cu > 0 {
                        let syncaddrs: std::vec::Vec<SocketAddr> = {
                            let mut syncer = syncerm.lock().await;
                            let myvec = syncer.connections.to_vec();
                            myvec
                            // myvec.choose_multiple(&mut rand::rng(), 2).cloned().collect()
                        };

                        for mut syncaddr in syncaddrs {
                            syncaddr.set_port(config::PORT);
                            c2push(
                                syncaddr,
                                Arc::clone(&client),
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

pub fn new_quic_client(source_addr: SocketAddr) -> Client {
    Client::builder()
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
    client: Arc<Client>,
    syncerm: AM<C2Syncer<S>>,
    graph: GraphId
) {

    // TODO: Is with_server_name required here ?
    let conn = client
        .connect(Connect::new(remote_addr).with_server_name("localhost"))
        .await;

    if let Ok(mut c) = conn {
        // c.keep_alive(true);
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
                let mut clientc = syncer.client.lock().await;    
                let tbuffers = &mut syncer.buffers;

                let cache = syncer.remote_heads.entry(remote_addr).or_default();

                requester.poll(
                    &mut buffer,
                    clientc.provider(),
                    cache,
                    &mut tbuffers.primary,
                ).unwrap()
            };

            buffer.truncate(len);
            buffer.shrink_to_fit();

            s.send_vectored(&mut [Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), buffer.into()]).await;

            let mut recv: Vec<u8, MAX_SYNC_MESSAGE_SIZE> = Vec::new();

            // println!("ABOUT TO RECEIVE");

            while let Ok(Some(data)) = s.receive().await {
                recv.extend_from_slice(&data);
            }

            {
                let syncer = &mut *syncerm.lock().await;
                let mut clientc = syncer.client.lock().await;
                let mut sinkc = syncer.sink.lock().await;
                let cache = syncer.remote_heads.entry(remote_addr).or_default();
                let tbuffers = &mut syncer.buffers;

                let recvdata = requester.receive(&recv);
                // println!("RECVDATA: {recvdata:?}");

                if let Ok(Some(cmds)) = recvdata {
                    let mut tx = clientc.transaction(graph);
                    clientc.add_commands(&mut tx, &mut *sinkc, &cmds, &mut tbuffers.primary);
                    clientc.commit(tx, &mut *sinkc, &mut tbuffers.primary);
                    if clientc.update_heads(
                        graph,
                        cmds.iter().filter_map(|cmd| cmd.address().ok()),
                        cache,
                        &mut tbuffers.primary,
                    ).is_err()
                    {
                        println!("ERROR UPDATING HEADS2");
                    }
                }
            }
            
        }
        c.close(0u32.into());
    }
}

pub async fn c2push<S: Sink<VmEffect>>(
    remote_addr: SocketAddr,
    client: Arc<Client>,
    syncerm: AM<C2Syncer<S>>,
    graph: GraphId
) {
    let conn = client
        .connect(Connect::new(remote_addr).with_server_name("localhost"))
        .await;
    
    if let Ok(mut c) = conn {
        c.keep_alive(true);
        // println!("Waiting for stream to start");
        let stream = c.open_bidirectional_stream().await;
        // println!("Stream has started !!");

        if let Ok(mut s) = stream {
            let mut responder = SyncResponder::new();

            let mut commands = Vec::new();

            // Random session ID
            use rand::prelude::*;
            let mut dst = [0u8; 16];
            rand::rng().fill_bytes(&mut dst);
            let session_id = u128::from_le_bytes(dst);

            {
                let mut syncerl = syncerm.lock().await;
                let cache = syncerl.remote_heads.entry(remote_addr).or_default();
                // println!("\n\nCACHE: {cache:?}\n\n\n");
                // let heads = cache.heads();
                // println!("\n\nCACHE_HEADS: {heads:?}\n\n\n");
                commands.extend_from_slice(cache.heads());
                // println!("TEST: {:?}", commands);
            }

            responder.receive(SyncRequestMessage::SyncRequest {
                session_id,
                graph_id: graph,
                max_bytes: 0,
                commands,
            });

            // {
            //     let syncer = &mut *syncerm.lock().await;
            //     let cache = syncer.remote_heads.entry(remote_addr).or_default();
            //     // println!("\n\nCACHE: {cache:?}\n\n\n");
            //     // let heads = cache.heads();
            //     // println!("\n\nCACHE_HEADS: {heads:?}\n\n\n");
            //     let mut clientc = syncer.client.lock().await;
            //     let buffers = &mut syncer.buffers;

            //     if let Ok(storage) = clientc.provider().get_storage(graph) {
            //         for command in &commands {
            //             if let Ok(Some(cmd_loc)) = storage.get_location(*command, &mut buffers.primary) {
            //                 cache.add_command(
            //                     storage,
            //                     *command,
            //                     cmd_loc,
            //                     &mut buffers.primary,
            //                 );
            //             }
            //         }
            //     }
            // }

            let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
            
                let syncaddrs: std::vec::Vec<SocketAddr> = {
                    let mut syncer = syncerm.lock().await;
                    let myvec = syncer.connections.to_vec();
                    myvec.choose_multiple(&mut rand::rng(), 2).cloned().collect()
                };
            {                
                let syncer = &mut *syncerm.lock().await;
                let mut clientc = syncer.client.lock().await;
                let tbuffers = &mut syncer.buffers;
                match responder.push(
                    &mut buffer,
                    clientc.provider(),
                    tbuffers
                ) {
                    Ok(len) => {
                        // println!("I am about to send my mfing data");
                        // println!("LENGTH: {len}");
                        buffer.truncate(len);
                        // buffer.shrink_to_fit();

                        if len > 0 {
                            // TODO: syncer is locked here, but its okay because UDP ?
                            s.send_vectored(&mut [Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), buffer.into()]).await;
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
    }
}

pub async fn run_c2syncer<S: Sink<VmEffect> + Send + 'static>(
    syncer: AM<C2Syncer<S>>,
    client: Arc<Client>,
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
