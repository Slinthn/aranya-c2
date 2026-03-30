mod common;
mod config;
mod policy;
mod c2syncer;

use std::{
    io::{Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use aranya_crypto::{CmdId, DeviceId};
use aranya_policy_text::Text;
use aranya_runtime::{Sink, VmEffect, vm_action};
use chrono::DateTime;
use tokio::time::{Duration, sleep};

use crate::{c2syncer::{c2push, c2sync, new_quic_client, run_c2syncer}, common::{C2Client, random_sync}};

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

fn print_header(aranya: &C2Client<OperatorSink>) {
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

async fn print_nodes(aranya: &C2Client<OperatorSink>) {
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

// async fn afc_listener() {
//     let listener = std::net::TcpListener::bind("127.0.0.1:4446").unwrap();

//     for stream in listener.incoming() {
//         let mut buffer = [0; 1024];

//         match stream.unwrap().read(&mut buffer) {
//             Ok(n) => {
//                 println!("Data: {:?}", &buffer[..n]);
//             }
//             Err(_) => {}
//         }

//         // if let Ok(Some(req)) = stream.unwrap().receive().await {
//         // println!("{:?}", req);
//         // }
//     }
// }

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

    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 4445);

    let mut aranya = C2Client::init(
        config::POLICY.to_string(),
        bind,
        OperatorSink::new()
    ).unwrap();

    rt.block_on(async move {
        let quica = {
            let mut syncbind = bind.clone();
            syncbind.set_port(4446);
            Arc::new(new_quic_client(syncbind))
        };

        tokio::spawn(
            run_c2syncer(
                Arc::clone(&aranya.c2syncerm),
                Arc::clone(&quica),
                bind
            )
        );

        let graph = match aranya.create_graph().await {
            Ok(v) => v,
            Err(_) => {
                print!("Failed to create Aranya graph...");
                return;
            }
        };

        // TODO: Insane testing environemnt skills
        let mut file = std::fs::File::create("src/graph.txt").unwrap();
        file.write_all(graph.as_array());
        // TODO: End skills

        print!("Working on Graph ID `{}`\n", graph);

        // TODO: AFC Test

        // tokio::spawn(async {
        //     afc_listener().await;
        // });

        // TODO: End AFC Test

        let aranyaa = Arc::new(aranya);
        let aranya = Arc::clone(&aranyaa);
        let quic = Arc::clone(&quica);

        tokio::spawn(async move {
            loop {
                let mut s = String::new();
                std::io::stdin()
                    .read_line(&mut s)
                    .expect("String read error");

                if s.starts_with("command ") {
                    let (_, args) = s.split_once(' ').unwrap();
                    print!("{}\n", args);

                    use std::str::FromStr;
                    let text = Text::from_str(args).unwrap();

                    aranya.do_action(vm_action!(execute_command(text))).await;

                    {
                        let syncaddrs = {
                            let syncerl = aranya.c2syncerm.lock().await;
                            syncerl.connections.to_vec()
                        };
                
                        for addr in syncaddrs {
                            c2push(
                                addr,
                                Arc::clone(&quic),
                                Arc::clone(&aranya.c2syncerm),
                                graph
                            ).await;

                            // Need to sleep otherwise connection will
                            //   not be made for some reason
                            sleep(Duration::from_millis(10)).await;
                        }
                    }

                } else if s.starts_with("connect ") {
                    let (_, args) = s.split_once(' ').unwrap();
                    
                    if let Ok(addr) = args.trim().parse::<SocketAddr>() {
                        let mut syncerl = aranya.c2syncerm.lock().await;
                        if !syncerl.connections.contains(&addr) {
                            syncerl.connections.push(addr);
                        }
                    } else {
                        println!("Invalid address!");
                    }
                } else if s.starts_with("qc ") {
                    let (_, args) = s.split_once(' ').unwrap();

                    if let Ok(amt) = args.trim().parse::<u8>() {
                        {
                            let mut syncerl = aranya.c2syncerm.lock().await;
                            for i in 1..amt+1 {
                                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, i)), 4445);
                                if !syncerl.connections.contains(&addr) {
                                    syncerl.connections.push(addr);
                                    println!("aaa {addr}")
                                }
                            }
                        }

                        // let syncaddrs = {
                        //     let mut syncerl = aranya.c2syncerm.lock().await;
                        //     syncerl.connections.to_vec()
                        // };

                        // for addr in syncaddrs {
                        //     sleep(Duration::from_millis(100)).await;
                        //     c2push(
                        //         addr,
                        //         Arc::clone(&quic),
                        //         Arc::clone(&aranya.c2syncerm),
                        //         graph
                        //     ).await;

                        //     // Need to sleep otherwise connection will
                        //     //   not be made for some reason
                        //     sleep(Duration::from_millis(100)).await;
                        // }

                        
                        // TODO: This is such a big hack. Without manually dropping
                        //   this var, it will stay locked forever. I have no fkin
                        //   idea why... (Whole program will hang for like eternity)
                        // sleep(Duration::from_millis(100)).await;
                        // let mut syncerl = aranya.c2syncerm.lock().await;
                        // drop(syncerl);
                        
                        // println!("DOne this shit!!");
                        // continue;
                    }
                }
            }
        });

        let aranya = Arc::clone(&aranyaa);
        let quic = Arc::clone(&quica);

        loop {
            sleep(Duration::from_millis(2000)).await;

            aranya
                .do_ephemeral_action(vm_action!(query_devices()))
                .await;

            console_clear();
            print_header(&aranya);
            print_nodes(&aranya).await;
            // aranya.do_action(vm_action!(heartbeat(aranya.keys.clone()))).await;

            let syncaddrs = {
                let mut syncer = aranya.c2syncerm.lock().await;
                random_sync(&mut syncer, Some(bind))
            };
                
            for addr in syncaddrs {
                c2push(
                    addr,
                    Arc::clone(&quic),
                    Arc::clone(&aranya.c2syncerm),
                    graph
                ).await;

                c2sync(
                    addr,
                    Arc::clone(&quic),
                    Arc::clone(&aranya.c2syncerm),
                    graph
                ).await;

                sleep(Duration::from_millis(10)).await;
            }
        }
    });
}
