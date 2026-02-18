mod common;
mod config;
mod policy;

use std::{
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
    },
    rc::Rc,
    cell::RefCell,
    sync::Arc,
};
use aranya_policy_vm::text;
use aranya_runtime::{Sink, VmEffect, vm_action};
use aranya_crypto::BaseId;

use tokio::sync::Mutex;

struct C2Sink {
    pub client2: Option<Arc<Mutex<common::Client<C2Sink>>>>,
    pub someinteger: u64
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
            print!("Effect received:\n{:?}\n", effect);
            if let aranya_policy_vm::Value::String(s) = effect.fields[0].value() {
                let out = std::process::Command::new(s).output().expect("Error exec command");
                let stdout = String::from_utf8_lossy(&out.stdout);
                print!("Out: {}\n", stdout);

                let thingy = &self.client2.as_ref();

                if let Some(client) = thingy.cloned() {
                        // print!("AAAAHHHHH22FDAFAFFFAAFAFFAF2123123=2\n");
                    
                    tokio::spawn(async move {
                        // print!("AAAAHHHHH222123123=2\n");
        let mut bytes = [0u8; 32];
                        // let test = command_executed {
                        //     cmd: effect.command,
                        //     result: text!("Hi")
                        // };

                        client.lock().await.do_action(vm_action!(command_executed(BaseId::default(), text!("LOL!")))).await;
                        // print!("AAAAHHHHH22222\n");
                    });
                } else {
                    // print!("LOLNO {}\n", self.someinteger);
                }
            }
        } else if effect.name == "CommandResult" {
            // print!("AAA\n");
        }

        // print!("AAAB\n");

    }

    fn rollback(&mut self) {
        // NOTE: No operation
    }
}

use aranya_runtime::storage::GraphId;

use tokio::time::{sleep, Duration};

use crate::policy::command_executed;

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
    let sync = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 4445);


    rt.block_on(async move {
        let mut aranya = common::Client::init(
            config::POLICY.to_string(),
            bind,
            C2Sink {
                client2: None,
                someinteger: 2
            },
        ).unwrap();
    let aaa = Arc::new(Mutex::new(aranya));

        {

        let haha : Arc<Mutex<common::Client<C2Sink>>> = Arc::clone(&aaa);
        
        let lolll = Arc::clone(&haha);
        
        let lol2 = &mut *lolll.lock().await;

        // match &lol2.sink.lock().await.client2 {
        //     Some(v) => print!("Something\n"),
        //     None => print!("Nothing\n")
        // };

        // print!("{:?}\n", lol2.sink.lock().await.client);        
        Arc::clone(&lol2.sink).lock().await.client2 = Some(haha);
        // Arc::clone(&lol2.sink).lock().await.someinteger = 45;
        // print!("{:?}\n", lol2.sink.lock().await.client);        

        // match &lol2.sink.lock().await.client2 {
        //     Some(v) => print!("Something\n"),
        //     None => print!("Nothing\n")
        // };
        let graph;
        // graph = match aranya.create_graph().await {
        //     Ok(v) => v,
        //     Err(_) => {
        //         print!("Failed to create Aranya graph...");
        //         return;
        //     }
        // };
        graph = GraphId::decode(config::GRAPH).unwrap();
        lol2.set_graph(graph);

        print!("Working on Graph ID `{}`\n", graph);
    
        // aranya.subscribe_to(sync).await;
    }

    {
        
        sleep(Duration::from_millis(1000)).await;
        
        let haha = Arc::clone(&aaa);
        
        let lolll = Arc::clone(&haha);
        
        let lol2 = &mut *lolll.lock().await;
        
        // match &lol2.sink.lock().await.client2 {
            //     Some(v) => print!("Something\n"),
            //     None => print!("Nothing\n")
            // };
            
            // lol2.sync_with(sync).await;
            // lol2.push_graph().await;
            
            // match &lol2.sink.lock().await.client2 {
            //     Some(v) => print!("Something\n"),
            //     None => print!("Nothing\n")
            // };
            
            // print!("{}\n", &lol2.sink.lock().await.someinteger);
            
            // aranya.sync_with(sync).await;
            // aranya.sync_with(sync).await;
            // sleep(Duration::from_millis(1000)).await;
            // aranya.do_action(aranya_runtime::vm_action!(hello())).await;
        }

        loop {
            sleep(Duration::from_millis(5000)).await;
            
            let haha = Arc::clone(&aaa);
            
            let lolll = Arc::clone(&haha);
            
            let lol2 = &mut *lolll.lock().await;
            lol2.subscribe_to(sync).await;
            // lol2.sync_with(sync).await;


            print!("Pushing\n");
            lol2.push_graph().await;
            print!("Done Pushing\n");
        }
    });
}
