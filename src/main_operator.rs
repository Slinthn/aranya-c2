mod c2syncer;
mod common;
mod config;

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use aranya_crypto::{CmdId, DeviceId};
use aranya_policy_text::Text;
use aranya_runtime::{Sink, VmEffect, vm_action};
use chrono::DateTime;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

use crate::c2syncer::{c2push, c2sync, new_quic_client, run_c2syncer};

struct DeviceStatus {
    device_id: DeviceId,
    last_heartbeat: i64,
    last_command: CmdId,
    last_output: String,
}

struct OperatorSink {
    pub devices: Vec<DeviceStatus>,
}

impl OperatorSink {
    fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }
}

impl Sink<VmEffect> for OperatorSink {
    fn begin(&mut self) {
        // NOTE: No operation
    }

    fn commit(&mut self) {
        // NOTE: No operation
    }

    fn consume(&mut self, effect: VmEffect) {
        if effect.name == "CommandResult" {
            if let aranya_policy_vm::Value::String(s) = effect.fields[1].value() {
                print!("Out: {}\n", s);
            }
        } else if effect.name == "QueryDevicesResult" {
            // print!("YEp\n");
            // println!("{:?}", effect);
            if let aranya_policy_vm::Value::Id(device_id) = effect.fields[0].value() {
                if let aranya_policy_vm::Value::Int(last_heartbeat) = effect.fields[2].value() {
                    if let aranya_policy_vm::Value::Id(last_command) = effect.fields[1].value() {
                        if let aranya_policy_vm::Value::String(last_output) =
                            effect.fields[3].value()
                        {
                            let devid = DeviceId::from_base(*device_id);
                            self.devices.retain(|v| v.device_id != devid);

                            self.devices.push(DeviceStatus {
                                device_id: DeviceId::from_base(*device_id),
                                last_heartbeat: *last_heartbeat,
                                last_command: CmdId::from_base(*last_command),
                                last_output: String::from(last_output.as_str()),
                            });
                        }
                    }
                }
            }
        }
    }

    fn rollback(&mut self) {
        // NOTE: No operation
    }
}

fn console_clear() {
    let _ = std::io::stdout().write_all(b"\x1B[2J\x1B[1;1H");
    let _ = std::io::stdout().flush();
}

fn print_header(aranya: &mut common::C2Client<OperatorSink>) {
    let _ = std::io::stdout().write_all(b"\x1B[1;1H");
    print!("Aranya C2 - Graph ID: ");

    match aranya.graph {
        Some(g) => {
            print!("{}", g);
        }
        None => {
            print!("No graph");
        }
    }

    print!(
        "\n\x1B[107;30m\nNode Identifier                              Last Heartbeat       Last Command ID                              Last Output"
    );
    print!("\x1B[0m\n");

    let _ = std::io::stdout().flush();
}

async fn print_nodes(aranya: &mut common::C2Client<OperatorSink>) {
    let sink = &mut *aranya.sink.lock().await;

    for device in &sink.devices {
        let niceoutput = device.last_output.replace("\n", "\\n");

        // if niceoutput.len() > 15 {
        //     niceoutput = niceoutput[0..15];
        // }

        println!(
            "{} {:?} {} {}",
            device.device_id,
            DateTime::from_timestamp(device.last_heartbeat, 0).unwrap(),
            device.last_command,
            niceoutput
        );
    }
}

async fn afc_listener() {
    let listener = std::net::TcpListener::bind("127.0.0.1:4446").unwrap();

    for stream in listener.incoming() {
        let mut buffer = [0; 1024];

        match stream.unwrap().read(&mut buffer) {
            Ok(n) => {
                println!("Data: {:?}", &buffer[..n]);
            }
            Err(_) => {}
        }

        // if let Ok(Some(req)) = stream.unwrap().receive().await {
        // println!("{:?}", req);
        // }
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

    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 4445);

    let mut aranya =
        common::C2Client::init(config::POLICY.to_string(), bind, OperatorSink::new()).unwrap();

    let mut syncbind = bind.clone();
    syncbind.set_port(4446);

    // let aranyam = Arc::new(Mutex::new(aranya));

    rt.block_on(async move {
        let quic = Arc::new(new_quic_client(syncbind));

        tokio::spawn(
            run_c2syncer(
                Arc::clone(&aranya.c2syncerm),
                Arc::clone(&quic),
                bind
            )
        );


        // TODO: AFC Test

        // tokio::spawn(async {
        //     afc_listener().await;
        // });

        // TODO: End AFC Test
        // let aranyam = Arc::new(Mutex::new(aranya));


        {
            // let aranyac = Arc::clone(&aranyam);
            // let aranyal = &mut *aranyac.lock().await;

            // let graph = GraphId::decode(config::GRAPH).unwrap();
            let graph = match aranya.create_graph().await {
                Ok(v) => v,
                Err(_) => {
                    print!("Failed to create Aranya graph...");
                    return;
                }
            };

            print!("Working on Graph ID `{}`\n", graph);
        }

        // let aranyac = Arc::clone(&aranyam);

        let c2syncerm = {
            // let aranyac = Arc::clone(&aranyam);
            // let aranyal = &mut *aranyac.lock().await;
            Arc::clone(&aranya.c2syncerm)
        };

        // let quicc = quic.clone();

        tokio::spawn(async {
            loop {
                let mut s = String::new();
                std::io::stdin()
                    .read_line(&mut s)
                    .expect("String read error");

                if s.starts_with("command ") {
                    let (_, args) = s.split_once(' ').unwrap();
                    print!("{}\n", args);
                    // let aranyal = &mut *aranyac.lock().await;

                    use std::str::FromStr;
                    let text = Text::from_str(args).unwrap();

                    aranya.do_action(vm_action!(execute_command(text))).await;

                    {
                        let syncaddrs = {
                            let mut syncerl = aranya.c2syncerm.lock().await;
                            syncerl.connections.to_vec()
                        };
                
                        for addr in syncaddrs {
                            c2push(
                                addr,
                                Arc::clone(&quic),
                                Arc::clone(&aranya.c2syncerm)
                            ).await;
                        }
                    }

                } else if s.starts_with("connect ") {
                    let (_, args) = s.split_once(' ').unwrap();
                    
                    if let Ok(addr) = args.trim().parse::<SocketAddr>() {
                        let mut syncerl = c2syncerm.lock().await;
                        if !syncerl.connections.contains(&addr) {
                            syncerl.connections.push(addr);
                        }
                    } else {
                        println!("Invalid address!");
                    }
                } else if s.starts_with("qc ") {
                    let (_, args) = s.split_once(' ').unwrap();

                    if let Ok(amt) = args.trim().parse::<u8>() {
                        for i in 1..amt {
                            let mut syncerl = c2syncerm.lock().await;
                            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, i)), 4445);
                            if !syncerl.connections.contains(&addr) {
                                syncerl.connections.push(addr);
                            }
                        }

                        {
                            let c2syncerm = {
                                // let aranyac = Arc::clone(&aranyac);
                                // let aranyal = &mut *aranyac.lock().await;
                                Arc::clone(&aranya.c2syncerm)
                            };

                            let syncaddrs = {
                                let mut syncerl = c2syncerm.lock().await;
                                syncerl.connections.to_vec()
                            };
                    
                            for addr in syncaddrs {
                                c2push(
                                    addr,
                                    Arc::clone(&quic),
                                    Arc::clone(&c2syncerm)
                                ).await;
                            }
                        }
                    }
                }
            }
        });

        loop {
            sleep(Duration::from_millis(1000)).await;

            {
                // let aranyac = Arc::clone(&aranyam);
                // let aranyal = &mut *aranyac.lock().await;

                aranya
                    .do_ephemeral_action(vm_action!(query_devices()))
                    .await;

                // console_clear();
                // print_header(aranya);
                // print_nodes(aranya).await;

                // c2sync(
                //     SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 3)), 4445),
                //     &quic,
                //     Arc::clone(&aranyal.c2syncerm)
                // ).await;

                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
                aranya.do_action(vm_action!(heartbeat())).await;
            }

            // let (c2syncerm, syncaddrs) = {
            //     // let aranyac = Arc::clone(&aranyam);
            //     // let aranyal = &mut *aranyac.lock().await;
            //     let syncaddrs = {
            //         let syncer = aranya.c2syncerm.lock().await;
            //         syncer.connections.to_vec()
            //     };
                
            //     (Arc::clone(&aranya.c2syncerm), syncaddrs)
            // };

            // for addr in syncaddrs {
            //     println!("Pushing");
            //     c2push(
            //         addr,
            //         Arc::clone(&quicc),
            //         Arc::clone(&c2syncerm)
            //     ).await;
            //     println!("Done");
            // }
        }
    });
}
