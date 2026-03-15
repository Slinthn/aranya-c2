use std::{
    sync::Arc,
    net::SocketAddr,
    collections::BTreeMap,
    time::Duration
};
use aranya_crypto::Rng;
use aranya_runtime::{
    Command,
    GraphId,
    MAX_SYNC_MESSAGE_SIZE,
    PeerCache,
    Sink,
    SyncRequestMessage,
    SyncRequester,
    SyncResponder,
    SyncType,
    TraversalBuffers,
    VmEffect
};
use bytes::Bytes;
use heapless::Vec;
use s2n_quic::{Client, Connection, Server, client::Connect, provider::limits::Limits};

use crate::{common::AM, config::{self, C2ClientState}};

pub struct C2Syncer<S: Sink<VmEffect>> {
    pub client: AM<C2ClientState>,
    pub sink: AM<S>,
    pub connections: std::vec::Vec<SocketAddr>,
}

async fn handle_request<S: Sink<VmEffect>>(
    mut conn: Connection,
    syncerm: AM<C2Syncer<S>>,
) {
    let stream = conn.accept_bidirectional_stream().await;
    if let Ok(Some(mut s)) = stream {
        // Add to connections list
        if let Ok(addr) = s.connection().remote_addr() {
            let mut syncerl = syncerm.lock().await;

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

            let sync_type = match postcard::take_from_bytes::<SyncType>(remaining) {
                Ok((sync_type, _remaining)) => sync_type,
                Err(_) => {
                    println!("Error parsing ");
                    return;
                }
            };

            if let SyncType::Poll { request } = sync_type {
                let mut buffer = vec![0u8; MAX_SYNC_MESSAGE_SIZE];

                let mut responder = SyncResponder::new();
                responder.receive(request);

                {
                    let syncer = syncerm.lock().await;
                    let mut clientc = syncer.client.lock().await;    
    
                    let mut cache = PeerCache::new();
                    let mut tbuffers = TraversalBuffers::new();

                    responder.poll(&mut buffer, clientc.provider(), &mut cache, &mut tbuffers);
                }

                s.send(buffer.into()).await;
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
    client: &Client,
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
            let mut tbuffers = TraversalBuffers::new();
            
            let syncaddrs = {
                let syncerl = syncerm.lock().await;
                syncerl.connections.to_vec()
            };

            {
                let syncer = syncerm.lock().await;
                let mut clientc = syncer.client.lock().await;    

                let mut cache = PeerCache::new();

                requester.poll(
                    &mut buffer,
                    clientc.provider(),
                    &mut cache,
                    &mut tbuffers.primary,
                );
            }

            s.send_vectored(&mut [Bytes::from(postcard::to_allocvec(&syncaddrs).unwrap()), buffer.into()]).await;

            let mut recv: Vec<u8, MAX_SYNC_MESSAGE_SIZE> = Vec::new();

            while let Ok(Some(data)) = s.receive().await {
                recv.extend_from_slice(&data);
            }

            {
                let syncer = syncerm.lock().await;
                let mut clientc = syncer.client.lock().await;
                let mut sinkc = syncer.sink.lock().await;
                let mut cache = PeerCache::new();

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

pub async fn run_c2syncer<S: Sink<VmEffect> + Send + 'static>(
    syncer: AM<C2Syncer<S>>,
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

                tokio::spawn(async move {
                    handle_request(conn, syncerc).await;
                });
            },
            None => {}
        }
    }
}
