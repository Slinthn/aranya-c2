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

use crate::c2syncer::{c2sync, new_quic_client};

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

    rt.block_on(async {
        // TODO: AFC Test

        tokio::spawn(async {
            afc_listener().await;
        });

        // TODO: End AFC Test

        let aranya =
            common::C2Client::init(config::POLICY.to_string(), bind, OperatorSink::new()).unwrap();

        let aranyam = Arc::new(Mutex::new(aranya));

        {
            let aranyac = Arc::clone(&aranyam);
            let aranyal = &mut *aranyac.lock().await;

            // let graph = GraphId::decode(config::GRAPH).unwrap();
            let graph = match aranyal.create_graph().await {
                Ok(v) => v,
                Err(_) => {
                    print!("Failed to create Aranya graph...");
                    return;
                }
            };

            print!("Working on Graph ID `{}`\n", graph);
        }

        let aranyac = Arc::clone(&aranyam);

        tokio::spawn(async move {
            loop {
                let mut s = String::new();
                std::io::stdin()
                    .read_line(&mut s)
                    .expect("String read error");

                if s.starts_with("command ") {
                    let (_, args) = s.split_once(' ').unwrap();
                    print!("{}\n", args);
                    let aranyal = &mut *aranyac.lock().await;

                    use std::str::FromStr;
                    let text = Text::from_str(args).unwrap();

                    aranyal.do_action(vm_action!(execute_command(text))).await;
                }
            }
        });

        let mut syncbind = bind.clone();
        syncbind.set_port(4446);
        let quic = new_quic_client(syncbind);

        loop {
            sleep(Duration::from_millis(100)).await;

            let aranyac = Arc::clone(&aranyam);
            let aranyal = &mut *aranyac.lock().await;

            // tokio::time::timeout(Duration::from_millis(1000), async {
            //     aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 1)), 4445)).await;
            // }).await;

            // tokio::time::timeout(Duration::from_millis(1000), async {
            //     aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 2)), 4445)).await;
            // }).await;

            // tokio::time::timeout(Duration::from_millis(1000), async {
            //     aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 3)), 4445)).await;
            // }).await;

            // tokio::time::timeout(Duration::from_millis(1000), async {
            //     aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 4)), 4445)).await;
            // }).await;

            // tokio::time::timeout(Duration::from_millis(1000), async {
            //     aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 5)), 4445)).await;
            // }).await;

            // let _ = tokio::time::timeout(Duration::from_millis(50000), async {
            //     let _ = aranyal
            //         .subscribe_to(SocketAddr::new(
            //             IpAddr::V4(Ipv4Addr::new(127, 0, 1, 2)),
            //             4445,
            //         ))
            //         .await;
            //     // aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 2)), 4445)).await;
            //     aranyal.push_graph().await;
            // })
            // .await;

            aranyal
                .do_ephemeral_action(vm_action!(query_devices()))
                .await;

            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            // aranyal.do_action(vm_action!(heartbeat())).await;
            console_clear();
            print_header(aranyal);
            print_nodes(aranyal).await;

            c2sync(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 3)), 4445),
                &quic,
                Arc::clone(&aranyal.c2syncerm)
            ).await;
        }
    });
}
