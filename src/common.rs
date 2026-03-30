use std::{
    sync::Arc,
    net::SocketAddr,
    collections::BTreeMap
};

use aranya_crypto::dangerous::spideroak_crypto;
use aranya_crypto::default::DefaultCipherSuite;
use aranya_crypto::keystore::fs_keystore;
use aranya_crypto::keystore::memstore::MemStore;
use aranya_libc::Path;
use aranya_runtime::linear::{
    libc::FileManager
};
use aranya_runtime::{
    ClientState, GraphId, Policy, PolicyError, PolicyId, PolicyStore, Sink, TraversalBuffers, VmEffect, VmPolicy, vm_action
};
use aranya_crypto::{
    DeviceId,
    Rng,
    default::DefaultEngine,
    id::IdExt
};
use aranya_crypto::{CmdId, Csprng, EncryptionKey, EncryptionPublicKey, Engine, IdentityKey, IdentityVerifyingKey, KeyStoreExt, SigningKey, VerifyingKey};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{
    Machine,
    ffi::FfiModule,
    CommandContext,
    MachineError,
    ffi::ffi
};
use rand::RngExt;
use rand::seq::{IndexedRandom, SliceRandom};
use tokio::{sync::{Mutex}};
use chrono::Utc;

use crate::config::{C2ClientState, C2StorageProvider};
use crate::c2syncer::{C2Syncer};

pub type C2VMPolicy = VmPolicy<DefaultEngine<Rng>>; 

pub struct C2PolicyStore {
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

pub struct C2Ffi;

#[ffi(module = "c2")]
impl C2Ffi {
    #[ffi_export(def = "function randomid() id")]
    pub(crate) fn randomid<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &E
    ) -> Result<CmdId, MachineError> {
        let mut bytes = [0u8; 32];
        // NOTE: It doesn't have to be this secure lol
        Rng.fill_bytes(&mut bytes);
        Ok(CmdId::from(bytes))
    }

    #[ffi_export(def = "function nullid() id")]
    pub(crate) fn nullid<E: aranya_crypto::Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &E
    ) -> Result<CmdId, MachineError> {
        let mut bytes = [0u8; 32];
        bytes[0] = 128;
        Ok(CmdId::from(bytes))
    }

    #[ffi_export(def = "function current_timestamp() int")]
    pub(crate) fn current_timestamp<E: aranya_crypto::Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &E
    ) -> Result<i64, MachineError> {
        Ok(Utc::now().timestamp())
    }
}

pub(crate) struct TestSink {
    cmds: Vec<Box<[u8]>>
}

impl TestSink {
    fn new() -> Self {
        Self {
            cmds: Vec::new()
        }
    }
}

impl Sink<&[u8]> for TestSink {
    fn begin(&mut self) {}
    
    fn consume(&mut self, effect: &[u8]) {
        self.cmds.push(effect.into());
    }

    fn rollback(&mut self) {}
    
    fn commit(&mut self) {}
}

// Shorthand for Arc Mutex just to aid readability
pub type AM<T> = Arc<Mutex<T>>;

pub struct C2Client<T: Sink<VmEffect>> {
    pub c2syncerm: AM<C2Syncer<T>>,
    pub cs: AM<C2ClientState>,
    pub sink: AM<T>,
    // pub syncer: AM<Syncer<C2PolicyStore, C2StorageProvider, T>>,
    pub graph: Option<GraphId>,
    pub store: fs_keystore::Store,
    pub eng: DefaultEngine<Rng, DefaultCipherSuite>,
    pub keys: crate::policy::PublicKeyBundle
}

struct PublicKeyBundle {
    ident_key: IdentityKey<DefaultCipherSuite>,
    sign_key: SigningKey<DefaultCipherSuite>,
    enc_key: EncryptionKey<DefaultCipherSuite>,
}

impl<T: Sink<VmEffect>> C2Client<T>
where 
    T: Sink<VmEffect> + Send + Sync + 'static
{
    pub fn init(
        policy_data: String,
        // TODO: REmove this
        _bind_addr: SocketAddr,
        clientsink: T
    ) -> Result<Self, ()> {
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
            aranya_envelope_ffi::Ffi::SCHEMA,
            aranya_device_ffi::FfiDevice::SCHEMA,
            aranya_perspective_ffi::FfiPerspective::SCHEMA,
            C2Ffi::SCHEMA,
            aranya_crypto_ffi::Ffi::<MemStore>::SCHEMA,
            aranya_idam_ffi::Ffi::<MemStore>::SCHEMA,
        ]).compile() {
            Ok(v) => v,
            Err(v) => {
                print!("Policy compliation error:\n{:?}\n", v);
                return Err(());
            }
        };

        let (engine, _key) = DefaultEngine::from_entropy(spideroak_crypto::default::Rng);
        let machine = Machine::from_module(module).unwrap();

        // TODO: No need for this rng because ident keys are used instead
        // let mut r = Rng::new();
        // let id = DeviceId::random(&mut r);

        // TODO: AFC test
        // let identity = IdentityKey::<DefaultCipherSuite>::new(&mut engine);
        // let encryption = EncryptionKey::<DefaultCipherSuite>::new(&mut engine);

        // let identity2 = IdentityKey::<DefaultCipherSuite>::new(&mut engine);
        // let encryption2 = EncryptionKey::<DefaultCipherSuite>::new(&mut engine);

        // let ch1 = UniChannel {
        //     parent_cmd_id: CmdId::default(),
        //     our_sk: &encryption,
        //     their_pk: &encryption2.public().unwrap(),
        //     seal_id: identity.id().unwrap(),
        //     open_id: identity2.id().unwrap(),
        //     label_id: LabelId::default()
        // };

        // let ch2 = UniChannel {
        //     parent_cmd_id: ch1.parent_cmd_id,
        //     our_sk: &encryption2,
        //     their_pk: &encryption.public().unwrap(),
        //     seal_id: identity2.id().unwrap(),
        //     open_id: identity.id().unwrap(),
        //     label_id: ch1.label_id
        // };
        

        // use aranya_fast_channels::{
        //     AfcState, AranyaState, Channel, Cli.ent, Directed, Error, LocalChannelId,
        //     crypto::Aes256Gcm,
        //     shm::{Flag, Mode, Path, ReadState, WriteState},
        // };

        // // TODO: Fix OpenOnly here
        // let write_state1: WriteState<DefaultCipherSuite, Rng> = WriteState::open(
        //     Path::from_bytes(b"/testing3\x00").unwrap(),
        //     Flag::OpenOnly, Mode::ReadWrite, 42, Rng
        // ).unwrap();

        // let state1 = aranya_fast_channels::Client::<ReadState<DefaultCipherSuite>>::new(
        //     ReadState::open(
        //         Path::from_bytes(b"/testing3\x00").unwrap(),
        //         Flag::OpenOnly, Mode::ReadWrite, 42
        //     ).unwrap()
        // );

        // let (mut eng, _) = DefaultEngine::from_entropy(Rng);
        // let UniSecrets { author, peer } = UniSecrets::new(&mut eng, &ch1).unwrap();

        // let channel1 = write_state1.add(Directed::SealOnly {
        //     seal: UniSealKey::from_author_secret(&ch1, author).unwrap().into_raw_key()
        // }, ch1.label_id, identity2.id().unwrap()).unwrap();


        // let ciphertext = {
        //     let mut dest = vec!(0u8; "Hello".len() + Client::<ReadState<DefaultCipherSuite>>::OVERHEAD);
        //     let mut ctx = state1.setup_seal_ctx(channel1).unwrap();
        //     state1.seal(&mut ctx, &mut dest, "Hello".as_bytes()).unwrap();
        //     dest
        // };

        // print!("{:?}\n", ciphertext);


        // let write_state2: WriteState<DefaultCipherSuite, Rng> = WriteState::open(
        //     Path::from_bytes(b"/testing4\x00").unwrap(),
        //     Flag::OpenOnly, Mode::ReadWrite, 42, Rng
        // ).unwrap();
    
        // let channel2 = write_state2.add(Directed::OpenOnly {
        //     open: UniOpenKey::from_peer_encap(&ch2, peer).unwrap().into_raw_key()
        // }, ch1.label_id, identity.id().unwrap()).unwrap();

        // let state2 = aranya_fast_channels::Client::<ReadState<DefaultCipherSuite>>::new(
        //     ReadState::open(
        //         Path::from_bytes(b"/testing4\x00").unwrap(),
        //         Flag::OpenOnly, Mode::ReadWrite, 42
        //     ).unwrap()
        // );


        // {
        //     let mut dest = vec!(0u8; ciphertext.len() - Client::<ReadState<DefaultCipherSuite>>::OVERHEAD);
        //     let mut ctx = state2.setup_open_ctx(channel2).unwrap();
        //     state2.open(&mut ctx, &mut dest, &ciphertext).unwrap();

        //     print!("{:?}\n", dest);
        
        // }


        // TODO: Change dir name ?
        let mut randdir = [0u8; 10];

        for i in 0..10 {
            let mut rng = rand::rng();
            randdir[i] = rng.sample(rand::distr::Alphanumeric);
        }

        // TODO: is /tmp really the best place for this
        let dirpath = Path::new("/tmp").join(Path::new(std::str::from_utf8(&randdir).unwrap()));

        // TODO: A custom implementation of FileManager could always require
        //   the creation of a directory instead of having this
        let _ = std::fs::create_dir(
            std::path::Path::new("/tmp").join(
                std::path::Path::new(
                    std::str::from_utf8(&randdir).unwrap()
                )
            )
        );

        let stdpath = std::path::Path::new("/tmp").join(
                std::path::Path::new(
                    std::str::from_utf8(&randdir).unwrap()
                )
            ).join(
                std::path::Path::new("keys")
            );
        
        let _ = std::fs::create_dir(&stdpath);

        // TODO: MemStore will not work because I have to clone it,
        //   so this has to work instead :O
        
        // let a = ;

        let mut store = fs_keystore::Store::open(stdpath).unwrap();

        // TODO: End AFC test

        // TODO: figure out how to not .clone() below
        // let store = MemStore::new();

        let keys = PublicKeyBundle {
            ident_key: IdentityKey::<DefaultCipherSuite>::new(&engine),
            sign_key: SigningKey::<DefaultCipherSuite>::new(&engine),
            enc_key: EncryptionKey::<DefaultCipherSuite>::new(&engine),
        };

        let lol = crate::policy::PublicKeyBundle {
            ident_key: postcard::to_vec::<IdentityVerifyingKey<DefaultCipherSuite>, 90>(&keys.ident_key.public().unwrap()).unwrap().to_vec(),
            sign_key: postcard::to_vec::<VerifyingKey<DefaultCipherSuite>, 90>(&keys.sign_key.public().unwrap()).unwrap().to_vec(),
            // TODO: Bro how long is this encryptionpublickey array meant to actually be ?
            enc_key: postcard::to_vec::<EncryptionPublicKey<DefaultCipherSuite>, 150>(&keys.enc_key.public().unwrap()).unwrap().to_vec(),
        };

        let id = keys.ident_key.id().unwrap();

        let policy = match VmPolicy::new(machine, engine.clone(), vec![
            Box::from(aranya_envelope_ffi::Ffi),
            Box::from(aranya_device_ffi::FfiDevice::new(id)),
            Box::from(aranya_perspective_ffi::FfiPerspective),
            Box::from(C2Ffi),
            // TODO: Is it okay to clone ??? - yes but only because its filesystem
            Box::from(aranya_crypto_ffi::Ffi::<fs_keystore::Store>::new(store.try_clone().unwrap())),
            Box::from(aranya_idam_ffi::Ffi::<fs_keystore::Store>::new(store.try_clone().unwrap())),
        ]) {
            Ok(v) => v,
            Err(v) => {
                print!("Failed to create VmPolicy:\n{:?}\n", v);
                return Err(());
            }
        };

        // Instantiate new Aranya client state
        let ps = C2PolicyStore { policy };

        let ms = C2StorageProvider::new(FileManager::new(dirpath).unwrap());
        let cs = Arc::new(Mutex::new(ClientState::new(ps, ms)));
        let sink = Arc::new(Mutex::new(clientsink));

        // New self-signed certificate for server
        // NOTE: Using config here
        // TODO: Look into how to create one per client
        // let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        // let key = ck.key_pair.serialize_pem();
        // let cert = ck.cert.pem();

        // Create server for incoming sync requests


        // let (tx, _rx) = mpsc::unbounded_channel();
        // let syncer = Arc::new(
        //     Mutex::new(
        //         Syncer::new(&*config::CERTIFICATE,
        //             Arc::clone(&cs),
        //             Arc::clone(&sink),
        //             tx,
        //             bind_addr
        //         ).unwrap()
        //     )
        // );

        // Start the Aranya syncer server
        // tokio::spawn(run_syncer(Arc::clone(&syncer), server, rx));

        // print!("{:?}", lol.sign_key);

        // println!("{:?}", );
        let _ = store.insert_key(&engine, keys.ident_key).unwrap();
        // println!("{ident:?}");
        let _ = store.insert_key(&engine, keys.sign_key).unwrap();
        let _ = store.insert_key(&engine, keys.enc_key).unwrap();

        let c2syncerm = Arc::new(Mutex::new(C2Syncer {
            client: Arc::clone(&cs),
            sink: Arc::clone(&sink),
            connections: Vec::new(),
            buffers: TraversalBuffers::new(),
            remote_heads: BTreeMap::new()
        }));

        Ok(C2Client {
            c2syncerm,
            cs,
            sink,
            // syncer,
            graph: None,
            store,
            eng: engine,
            keys: lol
        })
    }

    pub async fn create_graph(&mut self) -> Result<GraphId, ()> {
        let mut cs = self.cs.lock().await;
        let sink: &mut T = &mut *self.sink.lock().await;

        // let keys = PublicKeyBundle {
        //     ident_key: IdentityKey::<DefaultCipherSuite>::new(&self.eng),
        //     sign_key: SigningKey::<DefaultCipherSuite>::new(&self.eng),
        //     enc_key: EncryptionKey::<DefaultCipherSuite>::new(&self.eng),
        // };

        // TODO: Is it bad that i am creating a new DefaultEngine when
        //   I already have one in the init() function above ?
        // let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);

        // let test = postcard::to_vec::<IdentityVerifyingKey<DefaultCipherSuite>, 90>(&keys.ident_key.public().unwrap()).unwrap();
        // print!("{test:?}");

        // let lol = crate::policy::PublicKeyBundle {
        //     ident_key: keys.ident_key.public().unwrap().id().unwrap().as_bytes().to_vec(),
        //     sign_key: postcard::to_vec::<VerifyingKey<DefaultCipherSuite>, 90>(&keys.sign_key.public().unwrap()).unwrap().to_vec(),
        //     enc_key: keys.enc_key.public().unwrap().id().unwrap().as_bytes().to_vec(),
        // };

        // // print!("{:?}", lol.sign_key);

        // // println!("{:?}", );
        // let ident = self.store.insert_key(&self.eng, keys.ident_key).unwrap();
        // // println!("{ident:?}");
        // let sign = self.store.insert_key(&self.eng, keys.sign_key).unwrap();
        // let enc = self.store.insert_key(&self.eng, keys.enc_key).unwrap();

        // Retrieve the stored identity key (DeviceId is the key identifier, not a key type).
        // println!("{:?}", );
        // let _ = self.store.get_key::<DefaultEngine, SigningKey<DefaultCipherSuite>>(&self.eng, sign);
        // let _ = self.store.get_key::<DefaultEngine, EncryptionKey<DefaultCipherSuite>>(&self.eng, enc);

        // let a: Vec<u8> = self.store.get_key::<DefaultEngine, IdentityKey<DefaultCipherSuite>>(&eng, ident).unwrap().unwrap().public().unwrap().try_into().unwrap();


        // println!("{:?}", self.store.get_key::<DefaultEngine, IdentityKey<DefaultCipherSuite>>(&eng, ident).unwrap().unwrap().public().unwrap().to_bytes());
        // println!("{:?}", self.store.get_key::<DefaultEngine, IdentityKey<DefaultCipherSuite>>(&eng, ident).unwrap().unwrap());



        // println!("{:?}", self.store.get_key::<_, IdentityKey<DefaultCipherSuite>>(&eng, myid));

        let graph = match cs.new_graph(
            &vec![0],
            vm_action!(init(self.keys.clone())),
            sink
        ) {
            Ok(v) => v,
            Err(v) => {
                print!("New graph creation error:\n{:?}\n", v);
                return Err(());
            }
        };

        self.graph = Some(graph);

        // TODO: Delete wtf is this? i forgot i wrote this
        // match self.syncer.lock().await.push(graph) {
        //     Ok(_) => {},
        //     Err(v) => {
        //         print!("Error syncing new graph:\n{:?}\n", v);
        //     }
        // }

        return Ok(graph);
    }

    pub async fn do_action(&self, action: <C2VMPolicy as Policy>::Action<'_>) -> bool {
        let mut cs = self.cs.lock().await;
        let sink: &mut T = &mut *self.sink.lock().await;

        match self.graph {
            Some(graph) => {
                if cs.action(graph, sink, action).is_err() {
                    return false;
                }
            },
            None => {
                print!("Cannot do an action without creating a graph.\n");
            }
        }
        return true;
    }

    pub async fn do_ephemeral_action(&self, action: <C2VMPolicy as Policy>::Action<'_>) {
        let mut cs = self.cs.lock().await;
        let sink: &mut T = &mut *self.sink.lock().await;

        match self.graph {
            Some(graph) => {
                let mut msg_sink = TestSink::new();
                let mut session = cs.session(graph).unwrap();
                let _ = session.action(&cs, sink, &mut msg_sink, action);
            },
            None => {
                print!("Cannot do an action without creating a graph.\n");
            }
        }
    }

    // pub async fn sync_with(
    //     &mut self,
    //     _addr: SocketAddr
    // ) {
    //     // let graph = match self.graph {
    //     //     Some(graph) => graph,
    //     //     None => {
    //     //         print!("Cannot do this action without creating a graph.\n");
    //     //         return;
    //     //     }
    //     // };

    //     // let mut rng = Rng::new();
    //     // let req = SyncRequester::new(graph, &mut rng);

    //     // let mut syncer = self.syncer.lock().await;
    //     // let _ = syncer.sync(Arc::clone(&self.cs), addr, req, Arc::clone(&self.sink), graph).await;
    // }

    // pub async fn subscribe_to(
    //     &mut self,
    //     _addr: SocketAddr
    // ) -> Result<(), QuicSyncError> {
    //     // let graph = match self.graph {
    //     //     Some(graph) => graph,
    //     //     None => {
    //     //         print!("Cannot do this action without creating a graph.\n");
    //     //         // TODO: Kidna funny we are returning an OK when this is an error
    //     //         return Ok(());
    //     //     }
    //     // };

    //     // let mut rng = Rng::new();
    //     // let req = SyncRequester::new(graph, &mut rng);

    //     // let mut syncer = self.syncer.lock().await;
    //     // return syncer.subscribe(Arc::clone(&self.cs), req, 5, u64::MAX, addr).await;
    //     return Ok(());
    // }

    // pub async fn push_graph(&mut self) {
    //     // let graph = match self.graph {
    //     //     Some(graph) => graph,
    //     //     None => {
    //     //         print!("Cannot do this action without creating a graph.\n");
    //     //         return;
    //     //     }
    //     // };

    //     // let mut syncer = self.syncer.lock().await;
    //     // let _ = syncer.push(graph);
    // }

    // TODO: Replace with config infected node ?
    #[allow(dead_code)] // May not be used in all implementations
    pub fn set_graph(&mut self, graph: GraphId) {
        self.graph = Some(graph);
    }
}

pub fn random_sync<T: Sink<VmEffect>>(syncer: &mut C2Syncer<T>, bind: Option<SocketAddr>) -> Vec<SocketAddr> {
    if let Some(b) = bind {
        syncer.connections.retain(|&e| e != b);
    }
    let clonedvec = syncer.connections.to_vec();
    clonedvec.choose_multiple(&mut rand::rng(), 2).cloned().collect()
}
