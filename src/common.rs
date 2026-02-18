use std::{
    sync::Arc,
    net::SocketAddr
};

use aranya_runtime::{
    ClientState,
    GraphId,
    PolicyError,
    PolicyId,
    PolicyStore,
    Sink,
    VmEffect,
    VmPolicy,
    memory::MemStorageProvider,
    Policy,
    vm_action,
    SyncRequester
};
use aranya_crypto::{
    DeviceId,
    Rng,
    default::DefaultEngine,
    id::IdExt
};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{Machine, ffi::FfiModule};
use aranya_quic_syncer::{Syncer, run_syncer};
use tokio::{sync::{Mutex, mpsc}};
use s2n_quic::Server;

use crate::config;

pub type C2VMPolicy = VmPolicy<DefaultEngine<Rng>>; 

struct C2PolicyStore {
    policy: C2VMPolicy
}

impl PolicyStore for C2PolicyStore {
    type Policy = C2VMPolicy;
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
}

use aranya_crypto::Csprng;
use aranya_policy_vm::{CommandContext, MachineError, MachineErrorType, ffi::ffi};
pub struct MyFfi;

#[ffi(module = "myffi")]
impl MyFfi {
    #[ffi_export(def = "function haha() id")]
    pub(crate) fn haha<E: aranya_crypto::Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &mut E
    ) -> Result<aranya_crypto::policy::CmdId, aranya_policy_vm::MachineError> {
        let mut bytes = [0u8; 32];
        // NOTE: It doesn't have to be this secure lol
        let mut rng = Rng;
        rng.fill_bytes(&mut bytes);
        Ok(aranya_crypto::policy::CmdId::from(bytes))
    }

    #[ffi_export(def = "function nullid() id")]
    pub(crate) fn nullid<E: aranya_crypto::Engine>(
        &self,
        ctx: &CommandContext,
        _eng: &mut E
    ) -> Result<aranya_crypto::policy::CmdId, aranya_policy_vm::MachineError> {
        let mut bytes = [0u8; 32];
        Ok(aranya_crypto::policy::CmdId::from(bytes))
    }
}

pub struct Client<T: Sink<VmEffect>> {
    cs: Arc<Mutex<ClientState<C2PolicyStore, MemStorageProvider>>>,
    pub sink: Arc<Mutex<T>>,
    syncer: Arc<Mutex<Syncer<C2PolicyStore, MemStorageProvider, T>>>,
    graph: Option<GraphId>
}

impl<T: Sink<VmEffect>> Client<T>
where 
    T: Sink<VmEffect> + Send + Sync + 'static
{
    pub fn init(policy_data: String, bind_addr: SocketAddr, clientsink: T) -> Result<Self, ()> {
        // Compile policy
        let policy = match parse_policy_document(policy_data.as_str()) {
            Ok(v) => v,
            Err(v) => {
                print!("Policy parsing error:\n{}\n", v.message);
                return Err(());
            }
        };

        let module = match Compiler::new(&policy).ffi_modules(&vec![
            // NOTE: envelope messes up policy code, as it
            //   says Envelope is defined, but if I delete the
            //   struct definition, it then says it's not defined
            // aranya_envelope_ffi::Ffi::SCHEMA,
            aranya_device_ffi::FfiDevice::SCHEMA,
            aranya_device_ffi::FfiDevice::SCHEMA,
            aranya_perspective_ffi::FfiPerspective::SCHEMA,
            // aranya_crypto_ffi::Ffi::<Store>::SCHEMA,
            // aranya_idam_ffi::Ffi::<Store>::SCHEMA,
            MyFfi::SCHEMA
        ]).compile() {
            Ok(v) => v,
            Err(v) => {
                print!("Policy compliation error:\n{:?}\n", v);
                return Err(());
            }
        };

        let (engine, _key) = DefaultEngine::from_entropy(Rng);
        let machine = Machine::from_module(module).unwrap();

        let mut r = Rng::new();
        let id = DeviceId::random(&mut r);

        // TODO: figure out how to not .clone() below
        // let store = MemStore::new();

        let policy = match VmPolicy::new(machine, engine, vec![
            Box::from(aranya_device_ffi::FfiDevice::new(id)),
            Box::from(aranya_envelope_ffi::Ffi),
            Box::from(aranya_perspective_ffi::FfiPerspective),
            Box::from(MyFfi),
            // Box::from(aranya_crypto_ffi::Ffi::<MemStore>::new(store.clone())),
            // Box::from(aranya_idam_ffi::Ffi::<MemStore>::new(store))
        ]) {
            Ok(v) => v,
            Err(v) => {
                print!("Failed to create VmPolicy:\n{:?}\n", v);
                return Err(());
            }
        };

        // Instantiate new Aranya client state
        let ps = C2PolicyStore{ policy };
        let ms = MemStorageProvider::new();
        let cs = Arc::new(Mutex::new(ClientState::new(ps, ms)));
        let sink = Arc::new(Mutex::new(clientsink));

        // New self-signed certificate for server
        // NOTE: Using config here
        // TODO: Look into how to create one per client
        // let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        // let key = ck.key_pair.serialize_pem();
        // let cert = ck.cert.pem();

        // Create server for incoming sync requests
        let server = match Server::builder()
            .with_tls((config::CERTIFICATE, config::KEY)).unwrap()
            .with_io(bind_addr).unwrap()
            .start() {
                Ok(v) => v,
                Err(e) => {
                    print!("Failed to start server:\n{:?}\n", e);
                    return Err(());
                }
        };

        let (tx, rx) = mpsc::unbounded_channel();
        let syncer = Arc::new(
            Mutex::new(
                Syncer::new(&*config::CERTIFICATE,
                    Arc::clone(&cs),
                    Arc::clone(&sink),
                    tx,
                    bind_addr
                ).unwrap()
            )
        );

        // Start the Aranya syncer server
        tokio::spawn(run_syncer(Arc::clone(&syncer), server, rx));

        Ok(Client {
            cs,
            sink,
            syncer,
            graph: None
        })
    }

    pub async fn create_graph(&mut self) -> Result<GraphId, ()> {
        let csclone = Arc::clone(&self.cs);
        let mut cs = csclone.lock().await;
        let sinkclone = Arc::clone(&self.sink);
        let sink: &mut T = &mut *sinkclone.lock().await;

        let graph = match cs.new_graph(
            &vec![0],
            vm_action!(init()),
            sink
        ) {
            Ok(v) => v,
            Err(v) => {
                print!("New graph creation error:\n{:?}\n", v);
                return Err(());
            }
        };

        self.graph = Some(graph);

        match self.syncer.lock().await.push(graph) {
            Ok(_) => {},
            Err(v) => {
                print!("Error syncing new graph:\n{:?}\n", v);
            }
        }

        return Ok(graph);
    }

    // pub async fn set_graph(&mut self, graph: GraphId) {
    //     self.graph = Some(graph);
    // }

    pub async fn do_action(&self, action: <C2VMPolicy as Policy>::Action<'_>) {
        let csclone = Arc::clone(&self.cs);
        let mut cs = csclone.lock().await;
        let sinkclone = Arc::clone(&self.sink);
        let sink: &mut T = &mut *sinkclone.lock().await;

        match self.graph {
            Some(graph) => {
                let _ = cs.action(graph, sink, action);
            },
            None => {
                print!("Cannot do an action without creating a graph.\n");
            }
        }
    }

    pub async fn sync_with(&mut self, addr: SocketAddr) {
        let csclone = Arc::clone(&self.cs);
        let mut cs = csclone.lock().await;
        let sinkclone = Arc::clone(&self.sink);
        let sink: &mut T = &mut *sinkclone.lock().await;

        let graph = match self.graph {
            Some(graph) => graph,
            None => {
                print!("Cannot do this action without creating a graph.\n");
                return;
            }
        };

        let mut rng = Rng::new();
        let req = SyncRequester::new(graph, &mut rng);

        let mut syncer = self.syncer.lock().await;
        let _ = syncer.sync(&mut *cs, addr, req, sink, graph).await;
    }

    pub async fn subscribe_to(&mut self, addr: SocketAddr) {
        let csclone = Arc::clone(&self.cs);
        let mut cs = csclone.lock().await;
        let sinkclone = Arc::clone(&self.sink);
        let sink: &mut T = &mut *sinkclone.lock().await;

        let graph = match self.graph {
            Some(graph) => graph,
            None => {
                print!("Cannot do this action without creating a graph.\n");
                return;
            }
        };

        let mut rng = Rng::new();
        let req = SyncRequester::new(graph, &mut rng);

        let mut syncer = self.syncer.lock().await;
        let _ = syncer.subscribe(&mut *cs, req, 5, u64::MAX, addr).await;
    }

    pub async fn push_graph(&mut self) {
        let csclone = Arc::clone(&self.cs);
        let mut cs = csclone.lock().await;
        let sinkclone = Arc::clone(&self.sink);
        let sink: &mut T = &mut *sinkclone.lock().await;

        let graph = match self.graph {
            Some(graph) => graph,
            None => {
                print!("Cannot do this action without creating a graph.\n");
                return;
            }
        };

        let mut syncer = self.syncer.lock().await;
        let _ = syncer.push(graph);
    }

    pub fn set_graph(&mut self, graph: GraphId) {
        self.graph = Some(graph);
    }
}
