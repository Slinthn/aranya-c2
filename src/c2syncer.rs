use std::{
    sync::Arc,
    net::SocketAddr,
    collections::BTreeMap,
    time::Duration
};
use aranya_crypto::Rng;
use aranya_runtime::{
    Address, Command, GraphId, MAX_SYNC_MESSAGE_SIZE, PeerCache, Sink, SyncRequestMessage, SyncRequester, SyncResponder, SyncType, TraversalBuffers, VmEffect
};
use bytes::Bytes;
use heapless::Vec;
use s2n_quic::{Client, Connection, Server, client::Connect, provider::limits::Limits};

use crate::{common::AM, config::{self, C2ClientState}};

pub struct C2Syncer<S: Sink<VmEffect>> {
    pub client: AM<C2ClientState>,
    pub sink: AM<S>,
    pub connections: std::vec::Vec<SocketAddr>,
    pub buffers: TraversalBuffers
}

async fn handle_request<S: Sink<VmEffect>>(
    mut conn: Connection,
    client: Arc<Client>,
    syncerm: AM<C2Syncer<S>>,
) {
    let stream = conn.accept_bidirectional_stream().await;
    if let Ok(Some(mut s)) = stream {
        // Add to connections list
        if let Ok(mut addr) = s.connection().remote_addr() {
            let mut syncerl = syncerm.lock().await;

            addr.set_port(config::PORT);

            if !syncerl.connections.contains(&addr) {
                syncerl.connections.push(addr);
            }
        }

        if let Ok(Some(req)) = s.receive().await {
            let (peers, remaining) = match postcard::take_from_bytes::<std::vec::Vec<SocketAddr>>(&req) {
                Ok((peers, remaining)) => (peers, remaining),
                Err(_) => {
                    println!("Error parsing peers");
                    return;
                }
            };

            {
                let mut syncerl = syncerm.lock().await;
                for peer in peers {
                    if !syncerl.connections.contains(&peer) {
                        syncerl.connections.push(peer);
                    }
                }
            }

            // println!("{:?}", req);

            let (sync_type, remaining) = match postcard::take_from_bytes::<SyncType>(remaining) {
                Ok((sync_type, remaining)) => (sync_type, remaining),
                Err(e) => {
                    println!("Error parsing sync data");
                    println!("{}", e);
                    println!("{:?}", remaining);
                    return;
                }
            };

            if let SyncType::Poll { request } = sync_type {
                let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

                let mut responder = SyncResponder::new();
                responder.receive(request);

                let syncaddrs = {
                    let syncer = syncerm.lock().await;
                    syncer.connections.to_vec()
                };

                {
                    let mut syncer = &mut *syncerm.lock().await;
                    let mut clientc = syncer.client.lock().await;
                    let tbuffers = &mut syncer.buffers;
    
                    let mut cache = PeerCache::new();

                    responder.poll(&mut buffer, clientc.provider(), &mut cache, tbuffers);
                }

                s.send_vectored(&mut [Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), buffer.into()]).await;
            } else if let SyncType::Push { message, graph_id } = sync_type {
                let mut cache = PeerCache::new();

                let mut requester = SyncRequester::new_session_id(graph_id, message.session_id());
                if let Ok(Some(cmds)) = requester.get_sync_commands(message, remaining) && cmds.len() > 0 {
                    let count = {
                        let mut syncer = &mut *syncerm.lock().await;
                        let mut clientc = syncer.client.lock().await;
                        let mut sinkc = syncer.sink.lock().await;
                        let mut tbuffers = &mut syncer.buffers;

                        let mut tx = clientc.transaction(graph_id);
                        let count = clientc.add_commands(&mut tx, &mut *sinkc, &cmds, &mut tbuffers.primary);
                        clientc.commit(tx, &mut *sinkc, &mut tbuffers.primary);
                        clientc.update_heads(
                            graph_id,
                            cmds.iter().filter_map(|cmd| cmd.address().ok()),
                            &mut cache,
                            &mut tbuffers.primary,
                        );

                        count
                    };

                    println!("HELLOOOOOOOOOOOO {:?}", count);
                    
                    // Sync with everyone else with regard to
                    //   this/these new command(s)
                    if let Ok(cu) = count && cu > 0 {
                        let syncaddrs = {
                            let syncer = syncerm.lock().await;
                            syncer.connections.to_vec()
                        };

                        // for mut syncaddr in syncaddrs {
                        //     syncaddr.set_port(config::PORT);
                        //     c2push(
                        //         syncaddr,
                        //         Arc::clone(&client),
                        //         Arc::clone(&syncerm)
                        //     ).await;
                        // }
                    }
                }
            }
        }
    }
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
    syncerm: AM<C2Syncer<S>>
) {

    // TODO: Is with_server_name required here ?
    let conn = client
        .connect(Connect::new(remote_addr).with_server_name("localhost"))
        .await;

    if let Ok(mut c) = conn {
        c.keep_alive(true);
        let stream = c.open_bidirectional_stream().await;

        if let Ok(mut s) = stream {
            let graph = GraphId::decode(config::GRAPH).unwrap();
            let mut requester = SyncRequester::new(graph, Rng);
            
            let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
            
            let syncaddrs = {
                let syncerl = syncerm.lock().await;
                syncerl.connections.to_vec()
            };

            let (len, _) = {
                let mut syncer = &mut *syncerm.lock().await;
                let mut clientc = syncer.client.lock().await;    
                let mut tbuffers = &mut syncer.buffers;

                let mut cache = PeerCache::new();

                requester.poll(
                    &mut buffer,
                    clientc.provider(),
                    &mut cache,
                    &mut tbuffers.primary,
                ).unwrap()
            };

            buffer.truncate(len);
            buffer.shrink_to_fit();

            s.send_vectored(&mut [Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), buffer.into()]).await;

            let mut recv: Vec<u8, MAX_SYNC_MESSAGE_SIZE> = Vec::new();

            while let Ok(Some(data)) = s.receive().await {
                recv.extend_from_slice(&data);
            }

            {
                let syncer = &mut *syncerm.lock().await;
                let mut clientc = syncer.client.lock().await;
                let mut sinkc = syncer.sink.lock().await;
                let mut cache = PeerCache::new();
                let mut tbuffers = &mut syncer.buffers;

                if let Ok(Some(cmds)) = requester.receive(&recv) {
                    let mut tx = clientc.transaction(graph);
                    clientc.add_commands(&mut tx, &mut *sinkc, &cmds, &mut tbuffers.primary);
                    clientc.commit(tx, &mut *sinkc, &mut tbuffers.primary);
                    clientc.update_heads(
                        graph,
                        cmds.iter().filter_map(|cmd| cmd.address().ok()),
                        &mut cache,
                        &mut tbuffers.primary,
                    );
                }
            }
            
            c.close(0u32.into());
        }
    }
}

pub async fn c2push<S: Sink<VmEffect>>(
    remote_addr: SocketAddr,
    client: Arc<Client>,
    syncerm: AM<C2Syncer<S>>
) {
    let conn = client
        .connect(Connect::new(remote_addr).with_server_name("localhost"))
        .await;

    if let Ok(mut c) = conn {
        c.keep_alive(true);
        let stream = c.open_bidirectional_stream().await;

        if let Ok(mut s) = stream {
            let mut responder = SyncResponder::new();

            let mut commands = Vec::new();

            // Random session ID
            use rand::prelude::*;
            let mut dst = [0u8; 16];
            rand::rng().fill_bytes(&mut dst);
            let session_id = u128::from_le_bytes(dst);

            responder.receive(SyncRequestMessage::SyncRequest {
                session_id,
                graph_id: GraphId::decode(config::GRAPH).unwrap(),
                max_bytes: 0,
                commands: commands,
            });

            let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];
            
            let syncaddrs = {
                let syncerl = syncerm.lock().await;
                syncerl.connections.to_vec()
            };

            {
                let syncer = &mut *syncerm.lock().await;
                let mut clientc = syncer.client.lock().await;
                let tbuffers = &mut syncer.buffers;

                let mut cache = PeerCache::new();

                match responder.push(
                    &mut buffer,
                    clientc.provider(),
                    tbuffers
                ) {
                    Ok(_) => {
                        println!("{:?}", s.send_vectored(&mut [Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), buffer.into()]).await);
                    },
                    Err(_) => {}
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
