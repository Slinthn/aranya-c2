mod common;
mod config;

use std::net::{
    IpAddr,
    Ipv4Addr,
    SocketAddr
};

use aranya_runtime::{Sink, VmEffect};
use tokio::time::{sleep, Duration};
use aranya_policy_text::text;

struct OperatorSink;

impl Sink<VmEffect> for OperatorSink {
    fn begin(&mut self) {
        // NOTE: No operation
    }

    fn commit(&mut self) {
        // NOTE: No operation
    }

    fn consume(&mut self, effect: VmEffect) {
        print!("Hahaha\n {:?}\n", effect);
        if effect.name == "CommandResult" {
            // print!("Effect received:\n{:?}\n", effect);
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
    let sync = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 4445);

    rt.block_on(async {
        let mut aranya = common::Client::init(
            config::POLICY.to_string(),
            bind,
            OperatorSink
        ).unwrap();

        let graph;
        graph = match aranya.create_graph().await {
            Ok(v) => v,
            Err(_) => {
                print!("Failed to create Aranya graph...");
                return;
            }
        };
        // graph = GraphId::decode(config::GRAPH).unwrap();
        // aranya.set_graph(graph);

        print!("\x1B[2J\x1B[1;1H");
        std::io::stdout().flush();
        print!("Working on Graph ID `{}`\n", graph);
    
        // aranya.subscribe_to(sync).await;
        
        loop {
            sleep(Duration::from_millis(5000)).await;
            aranya.subscribe_to(sync).await;
            // aranya.sync_with(sync).await;
            aranya.push_graph().await;
            print!("Loop start\n");
            aranya.do_action(aranya_runtime::vm_action!(execute_command(text!("whoami")))).await;
        }
    });
}
