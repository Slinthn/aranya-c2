




extern crate aranya_crypto;
extern crate aranya_policy_compiler;
extern crate aranya_policy_lang;
extern crate aranya_policy_module;
extern crate aranya_policy_vm;
extern crate aranya_runtime;
extern crate aranya_envelope_ffi;
extern crate aranya_device_ffi;
extern crate aranya_idam_ffi;
extern crate aranya_crypto_ffi;
extern crate aranya_perspective_ffi;
extern crate aranya_quic_syncer;
extern crate rcgen;
extern crate tokio;
extern crate s2n_quic;
extern crate serde;
extern crate tracing_subscriber;

use std::{fs, sync::Arc, time::Duration, net::{IpAddr, Ipv4Addr, SocketAddr}};
use std::rc::Rc;

use aranya_model::ModelPolicyStore;
use tokio::{sync::{Mutex, mpsc}};
use serde::{Serialize, Deserialize};

use s2n_quic::Server;

use aranya_crypto::{BaseId, DeviceId, Identified, KeyStore, Rng, default::{DefaultCipherSuite, DefaultEngine}, engine::WrappedKey, id::{self, IdError, IdExt}, keystore::{fs_keystore::Store, memstore::MemStore}};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::{parse_policy_document};
use aranya_policy_module::Module;
use aranya_policy_vm::{Machine, ffi::FfiModule};
use aranya_quic_syncer::{Syncer, run_syncer};
use aranya_runtime::{ClientState, GraphId, PolicyError, PolicyId, PolicyStore, Sink, SyncRequester, VmEffect, VmPolicy, memory::MemStorageProvider, sync, vm_action};

struct C2PolicyStore {
    policy: VmPolicy<DefaultEngine<Rng>>
}

impl PolicyStore for C2PolicyStore {
    type Policy = VmPolicy<DefaultEngine<Rng>>;
    type Effect = VmEffect;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, PolicyError> {
        Ok(PolicyId::new(policy[0] as usize))
    }

    fn get_policy(&self, _id: aranya_runtime::PolicyId) -> Result<&Self::Policy, PolicyError> {
        Ok(&self.policy)
    }
}

// TODO: Can use ModelPolicyStore ?
impl C2PolicyStore {
    pub fn from_module(module: Module) -> Self {
        let (engine, _key) = DefaultEngine::from_entropy(Rng);
        // TODO: Match the unwrap here instaed of just unwrap
        let machine = Machine::from_module(module).unwrap();

        // TODO: unwrap here as well
        // let bundle = KeyBundle

        // KeyStore
        
        let mut r = Rng::new();
        let id = DeviceId::random(&mut r);

        let store = MemStore::new();

        let policy = VmPolicy::new(machine, engine, vec![
            Box::from(aranya_envelope_ffi::Ffi),
            Box::from(aranya_device_ffi::FfiDevice::new(id)),
            Box::from(aranya_perspective_ffi::FfiPerspective),
            Box::from(aranya_crypto_ffi::Ffi::<MemStore>::new(store.clone())),
            Box::from(aranya_idam_ffi::Ffi::<MemStore>::new(store)),
        ]).unwrap();

        Self { policy }
    }
}

const POLICY_FILE: &str = "src/policy.md";

struct C2Sink {
    
}

impl Sink<VmEffect> for C2Sink {
    fn begin(&mut self) {
        print!("Beginning\n");
    }

    fn commit(&mut self) {
        print!("Committing\n");
    }

    fn consume(&mut self, _effect: VmEffect) {
        print!("Consuming\n");
    }

    fn rollback(&mut self) {
        print!("Rollbacking\n");
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Lol(u64);
impl WrappedKey for Lol {}
impl Identified for Lol {
    type Id = BaseId;

    fn id(&self) -> Result<BaseId, IdError> {
        let data = (0 as u64).to_le_bytes();
        Ok(IdExt::new::<DefaultCipherSuite>(b"TestKey".as_slice(), core::iter::once(data.as_slice())))
    }
}

fn main() {
    tracing_subscriber::fmt::init();

    print!("AAAAA\n");
    // Open policy file
    let data = match fs::read_to_string(POLICY_FILE) {
        Ok(v) => v,
        Err(_) => {
            print!("Failed opening policy file \"{}\"", POLICY_FILE);
            return;
        }
    };

    // Compile policy
    let policy = match parse_policy_document(data.as_str()) {
        Ok(v) => v,
        Err(v) => {
            print!("Policy error: {}", v.message);
            return;
        }
    };


    // TODO: Could use fs_keystore::Store for owner??
    let store = MemStore::new();

    // store.try_insert(id!(1), Lol(1));

    // TODO: dont use unwrap here, expect maybe

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)                // optional, number of worker threads
        .thread_stack_size(100 * 1024 * 1024) // 100 MB stack per thread
        .enable_all()                     // enables I/O, timers, etc.
        .build()
        .unwrap();

    let module = Compiler::new(&policy).ffi_modules(&vec![
        // aranya_envelope_ffi::Ffi::SCHEMA,
        aranya_device_ffi::FfiDevice::SCHEMA,
        aranya_perspective_ffi::FfiPerspective::SCHEMA,
        aranya_crypto_ffi::Ffi::<Store>::SCHEMA,
        aranya_idam_ffi::Ffi::<Store>::SCHEMA,
    ]).compile().unwrap();

            let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        
            let key = ck.key_pair.serialize_pem();
            let cert = ck.cert.pem();

    rt.block_on(async {

        let syncer: Arc<Mutex<Syncer<C2PolicyStore, MemStorageProvider, C2Sink>>>;
        let mut syncer2: Arc<Mutex<Syncer<C2PolicyStore, MemStorageProvider, C2Sink>>>;
        let graph: GraphId;
        {
            let module = Compiler::new(&policy).ffi_modules(&vec![
                // aranya_envelope_ffi::Ffi::SCHEMA,
                aranya_device_ffi::FfiDevice::SCHEMA,
                aranya_perspective_ffi::FfiPerspective::SCHEMA,
                aranya_crypto_ffi::Ffi::<Store>::SCHEMA,
                aranya_idam_ffi::Ffi::<Store>::SCHEMA,
            ]).compile().unwrap();
            let ps = C2PolicyStore::from_module(module);
            let ms = MemStorageProvider::new();
            let mut cs = ClientState::new(ps, ms);
            let mut sink = C2Sink {};


            print!("Hello\n");
            graph = match cs.new_graph(&vec![0], vm_action!(init()), &mut sink) {
                Ok(v) => {
                    print!("Okay\n");
                    v
                },
                Err(v) => {
                    print!("Err\n");
                    print!("{:?}\n", v);
                    print!("{}\n", v);
                    return;
                }
            };
            print!("{:?}\n", graph);
            print!("{:?}\n", GraphId::default());
            cs.action(graph, &mut sink, vm_action!(hello())).unwrap();
            
            // let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    
            // let key = ck.key_pair.serialize_pem();
            // let cert = ck.cert.pem();

            let sink2 = Arc::new(Mutex::new(sink));
    
            // TODO: Enforce encryption
            let server = Server::builder().with_tls((&cert[..], &key[..])).unwrap().with_io("127.0.0.1:4444").unwrap().start().unwrap();
    
            let (tx, rx) = mpsc::unbounded_channel();
            syncer = Arc::new(Mutex::new(Syncer::new(&*cert.clone(), Arc::new(Mutex::new(cs)), sink2, tx, server.local_addr().unwrap()).unwrap()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    
            syncer.lock().await.push(graph);
            
            tokio::spawn(run_syncer(Arc::clone(&syncer), server, rx));
        }

        // sync::qui

        {
            let ps = C2PolicyStore::from_module(module);
            let ms = MemStorageProvider::new();
            let mut cs = Arc::new(Mutex::new(ClientState::new(ps, ms)));
            let mut sink = C2Sink {};

            // let _ = cs.new_graph(&vec![0], vm_action!(init(0)), &mut sink);

            let sink2 = Arc::new(Mutex::new(sink));
    
            let server = Server::builder().with_tls((&cert[..], &key[..])).unwrap().with_io("127.0.0.1:4445").unwrap().start().unwrap();
    
            let (tx, rx) = mpsc::unbounded_channel();
            syncer2 = Arc::new(Mutex::new(Syncer::new(&*cert.clone(), Arc::clone(&cs), Arc::clone(&sink2), tx, server.local_addr().unwrap()).unwrap()));
    
            tokio::spawn(run_syncer(Arc::clone(&syncer2), server, rx));

            tokio::time::sleep(Duration::from_secs(3)).await;

            let mut rng = Rng::new();
            // rng.r#gen()
            let mut req = SyncRequester::new(graph, &mut rng);

            let thing = Arc::clone(&cs);
            let mut csclone = thing.lock().await;

            let mut sinkclone = sink2.lock().await;

            print!("{:?}\n", graph);
            // print!(cs.lock().await.)

            syncer2.lock().await.sync(&mut csclone, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4444), req, &mut sinkclone, graph).await;
            // sync::sync();
            // sync::sync();
        
            // cs2.
        }
    
        // SyncRequester::new(storage_id, rng, server_address);
        // SyncRequester::new(storage_id, rng, server_address)

        tokio::time::sleep(Duration::from_secs(20)).await;
    
    });

    // KeyStore

    // aranya_quic_syncer::run_syncer();

    // sync::SyncRequester

    print!("Done something\n");
}
