mod common;
mod config;

use std::{
    sync::Arc,
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr
    }
};

use aranya_runtime::{Sink, VmEffect, vm_action};
use tokio::time::{sleep, Duration};
use aranya_policy_text::text;
use tokio::sync::Mutex;

struct OperatorSink;

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
        }
    }

    fn rollback(&mut self) {
        // NOTE: No operation
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
    // let sync = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 20, 1, 5)), 4445);
    let sync = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 2)), 4445);

    rt.block_on(async {
        let mut aranya = common::Client::init(
            config::POLICY.to_string(),
            bind,
            OperatorSink
        ).unwrap();

        let aranyam = Arc::new(Mutex::new(aranya));

        {
            let aranyac = Arc::clone(&aranyam);
            let aranyal = &mut *aranyac.lock().await;

            let graph;
            graph = match aranyal.create_graph().await {
                Ok(v) => v,
                Err(_) => {
                    print!("Failed to create Aranya graph...");
                    return;
                }
            };

            // print!("\x1B[2J\x1B[1;1H");
            // std::io::stdout().flush();
            print!("Working on Graph ID `{}`\n", graph);
        }

        let aranyac = Arc::clone(&aranyam);
    
        tokio::spawn(async move {
            loop {
                let mut s = String::new();
                std::io::stdin().read_line(&mut s).expect("String read error");

                if s.starts_with("command ") {
                    let (_, args) = s.split_once(' ').unwrap();
                    print!("{}\n", args);
                    let aranyal = &mut *aranyac.lock().await;
                    aranyal.do_action(vm_action!(execute_command(text!("whoami")))).await;
                }
            }
        });

        loop {
            sleep(Duration::from_millis(5000)).await;

            let aranyac = Arc::clone(&aranyam);
            let aranyal = &mut *aranyac.lock().await;
            
            print!("Subscribing\n");
            // aranyal.subscribe_to(sync).await;
            aranyal.subscribe_to(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 1)), 4445)).await;
            aranyal.subscribe_to(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 2)), 4445)).await;
            aranyal.subscribe_to(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 3)), 4445)).await;
            aranyal.subscribe_to(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 4)), 4445)).await;
            aranyal.subscribe_to(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 5)), 4445)).await;
            // aranyal.push_graph().await;

            // aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 1)), 4445)).await;
            // aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 2)), 4445)).await;
            // aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 3)), 4445)).await;
            // aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 4)), 4445)).await;
            // aranyal.sync_with(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 5)), 4445)).await;

            print!("Subscribed & Pushed\n")
            
        }
    });
}
