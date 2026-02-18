
extern crate aranya_crypto;
extern crate aranya_policy_compiler;
extern crate aranya_policy_lang;
extern crate aranya_policy_module;
extern crate aranya_policy_vm;
extern crate aranya_runtime;
extern crate aranya_quic_syncer;
extern crate rcgen;
extern crate tokio;
extern crate s2n_quic;
extern crate serde;
extern crate tracing_subscriber;

use std::fs;

const POLICY_FILE: &str = "src/policy.md";

mod common;
mod config;

fn main() {
    // Enable logging to terminal 
    tracing_subscriber::fmt::init();

    // Open policy file
    let data = match fs::read_to_string(POLICY_FILE) {
        Ok(v) => v,
        Err(_) => {
            print!("Failed opening policy file \"{}\"", POLICY_FILE);
            return;
        }
    };

    // Create new async runtime for the Aranya syncer.
    //   It needs a lot of stack memory
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(100 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let mut aranya_client = common::Client::init(data).unwrap();
        aranya_client.create_graph().await;
        // let graph: GraphId;
        {
            // // Create new graph
            // graph = match cs.new_graph(&vec![0], vm_action!(init()), &mut sink) {
            //     Ok(v) => v,
            //     Err(v) => {
            //         print!("New graph creation error:\n{:?}\n", v);
            //         return;
            //     }
            // };
            // cs.action(graph, &mut sink, vm_action!(hello())).unwrap();

            
            // let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    
            // let key = ck.key_pair.serialize_pem();
            // let cert = ck.cert.pem();

            // let sink2 = Arc::new(Mutex::new(sink));
    
            // tokio::spawn(run_syncer(Arc::clone(&syncer), server, rx));
        }

        // sync::qui

        // {
        //     let ps = C2PolicyStore::from_module(module);
        //     let ms = MemStorageProvider::new();
        //     let mut cs = Arc::new(Mutex::new(ClientState::new(ps, ms)));
        //     let mut sink = C2Sink {};

        //     // let _ = cs.new_graph(&vec![0], vm_action!(init(0)), &mut sink);

        //     let sink2 = Arc::new(Mutex::new(sink));
    
        //     let server = Server::builder().with_tls((&cert[..], &key[..])).unwrap().with_io("127.0.0.1:4445").unwrap().start().unwrap();
    
        //     let (tx, rx) = mpsc::unbounded_channel();
        //     syncer2 = Arc::new(Mutex::new(Syncer::new(&*cert.clone(), Arc::clone(&cs), Arc::clone(&sink2), tx, server.local_addr().unwrap()).unwrap()));
    
        //     tokio::spawn(run_syncer(Arc::clone(&syncer2), server, rx));

        //     tokio::time::sleep(Duration::from_secs(3)).await;

        //     let mut rng = Rng::new();
        //     // rng.r#gen()
        //     let mut req = SyncRequester::new(graph, &mut rng);

        //     let thing = Arc::clone(&cs);
        //     let mut csclone = thing.lock().await;

        //     let mut sinkclone = sink2.lock().await;

        //     print!("{:?}\n", graph);
        //     // print!(cs.lock().await.)

        //     syncer2.lock().await.sync(&mut csclone, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4444), req, &mut sinkclone, graph).await;
        //     // sync::sync();
        //     // sync::sync();
        
        //     // cs2.
        // }
    
        // SyncRequester::new(storage_id, rng, server_address);
        // SyncRequester::new(storage_id, rng, server_address)

        // tokio::time::sleep(Duration::from_secs(20)).await;
    
    });

    // KeyStore

    // aranya_quic_syncer::run_syncer();

    // sync::SyncRequester

    print!("Done something\n");
}
