use std::{
    str::FromStr,
    path::Path,
    fs
};

use aranya_crypto::dangerous::spideroak_crypto::aead::Aead;
use aranya_crypto::dangerous::spideroak_crypto::import::Import;
use aranya_crypto::dangerous::spideroak_crypto::keys::SecretKey;
use aranya_crypto::default::DefaultCipherSuite;
use aranya_crypto::keystore::fs_keystore::Store;
use aranya_crypto::keystore::memstore::MemStore;
use aranya_runtime::linear::{
    libc::FileManager
};
use aranya_runtime::{
    GraphId, PolicyError, PolicyId, PolicyStore, Sink, VmEffect, VmPolicy, vm_action
};
use aranya_crypto::{
    Rng,
    default::DefaultEngine
};
use aranya_crypto::{CipherSuite, CmdId, Csprng, DeviceId, EncryptionKey, EncryptionPublicKey, Engine, Identified, IdentityKey, IdentityVerifyingKey, KeyStoreExt, SigningKey, VerifyingKey};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{
    Machine,
    ffi::FfiModule,
    CommandContext,
    MachineError,
    ffi::ffi
};
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::config::{C2ClientState, C2StorageProvider};
use crate::policy::PublicKeyBundle;

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

// pub(crate) struct TestSink {
//     cmds: Vec<Box<[u8]>>
// }

// impl TestSink {
//     fn new() -> Self {
//         Self {
//             cmds: Vec::new()
//         }
//     }
// }

// impl Sink<&[u8]> for TestSink {
//     fn begin(&mut self) {}
    
//     fn consume(&mut self, effect: &[u8]) {
//         self.cmds.push(effect.into());
//     }

//     fn rollback(&mut self) {}
    
//     fn commit(&mut self) {}
// }

// TODO: rm comment - Aead key, lol i had to fight rust to figure out this type wtf, before i was
//   using AeadKey<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>
pub type AeadKey = <<DefaultCipherSuite as CipherSuite>::Aead as Aead>::Key;

pub struct C2Client<'a> {
    pub engine: DefaultEngine<Rng, DefaultCipherSuite>,
    // TODO: Bro what should this type actually be ? wtf...
    // pub key: AeadKey,
    pub config_dir: &'a Path
}

pub struct PrivateKeyBundle {
    pub ident_key: IdentityKey<DefaultCipherSuite>,
    pub sign_key: SigningKey<DefaultCipherSuite>,
    pub enc_key: EncryptionKey<DefaultCipherSuite>
}

// TODO: I really need to stop calling these things C2ThisThatTheOther
#[derive(Serialize, Deserialize)]
pub struct C2Config {
    #[serde(default)]
    ident_id: String,
    #[serde(default)]
    sign_id: String,
    #[serde(default)]
    enc_id: String,
    #[serde(default)]
    graph_id: String
}


impl<'a> C2Client<'a> {
    pub fn new(config_dir: &'a Path) -> Self {
        let confpath = config_dir.join(Path::new("key.bin"));
        // TODO: copied in new_engine
        let engine = match fs::read(&confpath) {
            Ok(data) => {
                let key = Import::import(data.as_slice()).expect("Could not retrieve key");
                DefaultEngine::new(&key, Rng)
            },
            Err(_) => {
                let (engine, key): (DefaultEngine, AeadKey) =
                    DefaultEngine::from_entropy(Rng);

                let _ = fs::write(
                    config_dir.join(Path::new("key.bin")),
                    key.try_export_secret()
                        .expect("Could not export secret")
                        .into_bytes()
                );

                engine
            }
        };

        C2Client {
            engine,
            config_dir
        }

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
        // TODO: End AFC test


        // TODO: Change dir name ?

        // let c2syncerm = Arc::new(Mutex::new(C2Syncer {
        //     client: Arc::clone(&cs),
        //     sink: Arc::clone(&sink),
        //     connections: Vec::new(),
        //     buffers: TraversalBuffers::new(),
        //     remote_heads: BTreeMap::new()
        // }));
    }

    // TODO: Can I make it not pass config_dir and instead store?
    pub fn create_policy(
        &self,
        policy_data: &str,
        id: DeviceId
    ) -> Result<VmPolicy<DefaultEngine>, ()> {
        let store = Store::open(self.config_dir).unwrap();

        // Compile policy
        let policy = match parse_policy_document(policy_data) {
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

        let machine = Machine::from_module(module).unwrap();

        // TODO: TEST
        // let (engine, key): (DefaultEngine, AeadKey<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>) = DefaultEngine::from_entropy(Rng);

        match VmPolicy::new(machine, self.engine.clone(), vec![
            Box::from(aranya_envelope_ffi::Ffi),
            Box::from(aranya_device_ffi::FfiDevice::new(id)),
            Box::from(aranya_perspective_ffi::FfiPerspective),
            Box::from(C2Ffi),
            // TODO: Is it okay to clone ??? - yes but only because its filesystem
            Box::from(aranya_crypto_ffi::Ffi::<Store>::new(store.try_clone().unwrap())),
            Box::from(aranya_idam_ffi::Ffi::<Store>::new(store.try_clone().unwrap())),
        ]) {
            Ok(v) => Ok(v),
            Err(v) => {
                print!("Failed to create VmPolicy:\n{:?}\n", v);
                return Err(());
            }
        }
    }

    pub fn new_engine(&mut self) {
        let (engine, key): (DefaultEngine, AeadKey) = DefaultEngine::from_entropy(Rng);
        let _ = fs::write(self.config_dir.join(Path::new("key.bin")), key.try_export_secret().expect("Could not export secret").into_bytes());
        self.engine = engine;
    }

    // TODO: Really need &self here?
    pub fn init_aranya(
        &self,
        policy: VmPolicy<DefaultEngine>
    ) -> C2ClientState {
        C2ClientState::new(
            C2PolicyStore { policy },
            C2StorageProvider::new(FileManager::new(self.config_dir).unwrap())
        )
    }

    pub fn load_keys(&self) -> PrivateKeyBundle {
        let store = Store::open(self.config_dir).unwrap();
        // let id = keybundle.ident_key.id().unwrap();

        let conf = self.load_config();

        // Load ID of keys from config
        let ident_id = <<IdentityKey<DefaultCipherSuite> as Identified>::Id>::from_str(&conf.ident_id).expect("ident_id");
        let sign_id = <<SigningKey<DefaultCipherSuite> as Identified>::Id>::from_str(&conf.sign_id).expect("sign_id");
        let enc_id = <<EncryptionKey<DefaultCipherSuite> as Identified>::Id>::from_str(&conf.enc_id).expect("enc_id");

        // TODO: Error handling for non-existant config (remove unwrap shit)

        // TODO: Temporary
        println!("{}", ident_id);
        // println!("{:?}", store.get_key(&self.engine, ident_id));

        // Load private keys from Aranya store via public key/ID
        PrivateKeyBundle {
            ident_key: store.get_key(&self.engine, ident_id).unwrap().unwrap(),
            sign_key: store.get_key(&self.engine, sign_id).unwrap().unwrap(),
            enc_key: store.get_key(&self.engine, enc_id).unwrap().unwrap()
        }
    }

    // Load the C2 Aranya config
    fn load_config(&self) -> C2Config {
        // TODO: Make "config.yaml" a constant
        let confpath = self.config_dir.join(Path::new("config.yaml"));

        // Read data or default to no data
        let data = match fs::read(&confpath) {
            Ok(data) => String::from_utf8(data).expect("Lol no utf8"),
            Err(_) => String::new()
        };

        return serde_yaml::from_str(&data)
            .expect("Lol no serde_yaml::from_str");
    }

    // Write to the C2 Aranya config file
    fn write_config(&self, config: &C2Config) {
        let confpath = self.config_dir.join(Path::new("config.yaml"));
        let yaml = serde_yaml::to_string(config).expect("Could not write yaml");
        let _ = fs::write(&confpath, yaml);
    }

    // Generate a set of identify, signing, and encryption keys.
    // Will also write the keys to the config file
    pub fn create_new_keys(&self) -> PrivateKeyBundle {
        let mut store = Store::open(self.config_dir).unwrap();

        let ident_key = IdentityKey::<DefaultCipherSuite>::new(&self.engine);
        let sign_key = SigningKey::<DefaultCipherSuite>::new(&self.engine);
        let enc_key = EncryptionKey::<DefaultCipherSuite>::new(&self.engine);

        let _ = store.insert_key(&self.engine, ident_key.clone()).unwrap();
        let _ = store.insert_key(&self.engine, sign_key.clone()).unwrap();
        let _ = store.insert_key(&self.engine, enc_key.clone()).unwrap();

        let mut conf = self.load_config();
        conf.ident_id = ident_key.id().unwrap().to_string();
        conf.sign_id = sign_key.id().unwrap().to_string();
        conf.enc_id = enc_key.id().unwrap().to_string();
        self.write_config(&conf);

        return PrivateKeyBundle {
            ident_key,
            sign_key,
            enc_key
        };
    }

    // Create a new Aranya graph (with an Init command) and write
    //   it to the Aranya config
    pub fn create_graph<S: Sink<VmEffect>>(
        &mut self,
        cs: &mut C2ClientState,
        sink: &mut S,
        privkeys: &PrivateKeyBundle
    ) -> Result<GraphId, ()> {
        let pubkeys = PublicKeyBundle {
            ident_key: postcard::to_vec::<IdentityVerifyingKey<DefaultCipherSuite>, 90>(&privkeys.ident_key.public().unwrap()).unwrap().to_vec(),
            sign_key: postcard::to_vec::<VerifyingKey<DefaultCipherSuite>, 90>(&privkeys.sign_key.public().unwrap()).unwrap().to_vec(),
            // TODO: Bro how long is this encryptionpublickey array meant to actually be ?
            enc_key: postcard::to_vec::<EncryptionPublicKey<DefaultCipherSuite>, 150>(&privkeys.enc_key.public().unwrap()).unwrap().to_vec(),
        };

        match cs.new_graph(
            &vec![0],
            vm_action!(init(pubkeys)),
            sink
        ) {
            Ok(graph_id) => {
                self.set_graph(graph_id);
                Ok(graph_id)
            },
            Err(v) => {
                print!("New graph creation error:\n{:?}\n", v);
                Err(())
            }
        }
    }

    // pub fn call_action(
    //     &self,
    //     cs: &mut C2ClientState,
    //     sink: &mut S,
    //     graph: GraphId,
    //     action: <C2VMPolicy as Policy>::Action<'_>
    // ) {
    //     if let Err(e) = cs.action(graph, sink, action) {
    //         eprintln!("Error calling action: {}", e);
    //     }
    // }

    // pub async fn do_ephemeral_action(&self, action: <C2VMPolicy as Policy>::Action<'_>) {
    //     let mut cs = self.cs.lock().await;
    //     let sink: &mut T = &mut *self.sink.lock().await;

    //     match self.graph {
    //         Some(graph) => {
    //             let mut msg_sink = TestSink::new();
    //             let mut session = cs.session(graph).unwrap();
    //             let _ = session.action(&cs, sink, &mut msg_sink, action);
    //         },
    //         None => {
    //             print!("Cannot do an action without creating a graph.\n");
    //         }
    //     }
    // }

    // TODO: Replace with config infected node ?
    #[allow(dead_code)] // May not be used in all implementations
    pub fn set_graph(&mut self, graph_id: GraphId) {
        let mut conf = self.load_config();
        conf.graph_id = graph_id.to_string();
        self.write_config(&conf);
    }

    pub fn get_graph(&mut self) -> GraphId {
        let mut conf = self.load_config();
        return GraphId::decode(conf.graph_id)
            .expect("Could not decode graph ID from config");
    }
}

// 