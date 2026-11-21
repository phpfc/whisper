mod cancel;
mod candidates;
mod cli;
mod code;
mod connect;
mod crypto;
mod doctor;
mod gather;
mod keys;
mod portmap;
mod session;
mod signal;
mod stun;
mod util;
mod wire;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use mainline::async_dht::AsyncDht;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use cancel::{Cancel, Cancelled};
use candidates::{infer_kind, select_direct, Candidate};
use cli::P2PChat;
use code::SessionCode;
use connect::{connect, unix_ms, ConnectArgs, ConnectError, Connection, PeerInfo, Role, Timeouts};
use gather::{gather, Gathered};
use keys::{derive_psk, SessionKeys, SessionSecret};
use portmap::PortMap;
use session::validate_username;
use signal::{public_dht, spawn, Signaling};

/// How often each peer looks for the other's record on the DHT.
const SIGNAL_POLL: Duration = Duration::from_secs(3);

const DHT_UNAVAILABLE: &str = "DHT unavailable; only direct connections will work.";

/// Test hooks, read from the environment only (there is no CLI flag for them).
/// The NAT lab drives two peers with these, plus `WHISPER_STUN_SERVERS` and
/// `WHISPER_DHT_BOOTSTRAP`.
///
/// `=1`: once connected, print `CONNECTED via {path}` and exit 0 instead of
/// opening the chat. A failure to connect still exits non-zero.
const EXIT_ON_CONNECT_ENV: &str = "WHISPER_TEST_EXIT_ON_CONNECT";
/// The session creator writes its code to this file.
const CODE_FILE_ENV: &str = "WHISPER_TEST_CODE_FILE";

const NO_DHT_NO_ADDRESS: &str = "The DHT is unreachable and this code has no direct address, so the other peer cannot be found. Check that this network allows UDP traffic.";

#[derive(Parser)]
#[command(name = "whisper")]
#[command(about = "Secure P2P chat in the terminal. Zero configuration, no servers needed.")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new chat session and wait for someone to join
    Create {
        /// Your username
        #[arg(short, long)]
        username: String,

        /// Optional extra password (both peers must use the same one)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Join an existing chat session
    Join {
        /// Session code (given by the session creator)
        code: String,

        /// Your username
        #[arg(short, long)]
        username: String,

        /// Optional extra password (both peers must use the same one)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Check whether this network can host or join sessions
    Doctor,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Before anything is opened on the router, so that Ctrl-C at any point
    // can still release it (see `cancel`).
    let cancel = Cancel::install().await;

    let result = match cli.command {
        Commands::Create { username, password } => {
            create_session(&username, non_empty(&password), &cancel).await
        }
        Commands::Join {
            code,
            username,
            password,
        } => join_session(&code, &username, non_empty(&password), &cancel).await,
        Commands::Doctor => doctor::run(&cancel).await,
    };

    match result {
        // Whatever was open has been released by now.
        Err(e) if e.is::<Cancelled>() => {
            println!("\nCancelled.");
            std::process::exit(130);
        }
        result => result,
    }
}

/// An empty password is the same as none: both derive the same key.
fn non_empty(password: &Option<String>) -> Option<&str> {
    password.as_deref().filter(|p| !p.is_empty())
}

fn exit_on_connect() -> bool {
    std::env::var(EXIT_ON_CONNECT_ENV).is_ok_and(|v| v == "1")
}

/// Writes `code` and a newline to `path`. The file shows up complete: it is
/// written next to `path` and renamed, so a script polling for it never reads
/// half a code.
fn write_code_file(path: &Path, code: &str) -> Result<()> {
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    let written = std::fs::write(&temp, format!("{code}\n"))
        .and_then(|()| std::fs::rename(&temp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written.with_context(|| format!("could not write the session code to {}", path.display()))
}

fn check_username(username: &str) -> Result<()> {
    validate_username(username).map_err(|e| anyhow::anyhow!("Invalid username: {}", e))
}

/// Binds the sockets and learns how this machine can be reached.
async fn gather_network(cancel: &Cancel) -> Result<Gathered> {
    println!("Gathering network info...");
    let gathered = gather(cancel).await?;
    if let Some(port) = gathered.mapped_port() {
        println!("UDP port {port} opened on your router (closed on exit)");
    }
    Ok(gathered)
}

/// A receiver that never yields: nobody signals us when the DHT is down, and
/// only the addresses we already know can work.
fn closed_signal() -> mpsc::Receiver<PeerInfo> {
    let (_tx, rx) = mpsc::channel(1);
    rx
}

/// A DHT node being started.
type DhtStart = JoinHandle<std::io::Result<AsyncDht>>;

/// Starts the DHT node while the network is still being gathered, so it has
/// bootstrapped by the time we publish. Off the async workers: the node
/// resolves the bootstrap hostnames with blocking DNS lookups before it
/// returns, which can stall for seconds on a bad network.
fn start_dht() -> DhtStart {
    tokio::task::spawn_blocking(public_dht)
}

/// Publishes our candidates over the DHT and returns the peer's as they show
/// up. `None` when the DHT node could not start. Ctrl-C releases the router
/// mapping, like everywhere else.
async fn signal_over_dht(
    dht: DhtStart,
    role: Role,
    keys: &SessionKeys,
    gathered: &mut Gathered,
    cancel: &Cancel,
) -> Result<Option<mpsc::Receiver<PeerInfo>>> {
    let node = match cancel.run(dht).await {
        Ok(started) => started.ok().and_then(Result::ok),
        Err(cancelled) => {
            close_portmap(gathered.portmap.take()).await;
            return Err(cancelled.into());
        }
    };
    let Some(node) = node else {
        return Ok(None);
    };
    let info = PeerInfo {
        candidates: gathered.candidates.clone(),
        summary: gathered.summary.clone(),
        published_ms: unix_ms(),
    };
    Ok(Some(spawn(
        Signaling::new(keys, node),
        role,
        info,
        SIGNAL_POLL,
    )))
}

/// The DHT is down. A joiner can still try the addresses in the code, but
/// with none there is nobody to try.
fn without_dht(code: &SessionCode) -> Result<mpsc::Receiver<PeerInfo>> {
    if code.direct.is_empty() {
        bail!(NO_DHT_NO_ADDRESS);
    }
    println!("{DHT_UNAVAILABLE}");
    Ok(closed_signal())
}

async fn create_session(username: &str, password: Option<&str>, cancel: &Cancel) -> Result<()> {
    check_username(username)?;
    let dht = start_dht();
    let mut gathered = gather_network(cancel).await?;

    let secret = SessionSecret::generate();
    let keys = SessionKeys::derive(&secret);
    let code = SessionCode {
        secret,
        direct: select_direct(&gathered.candidates),
    };

    let encoded = code.encode();
    println!();
    println!("========================================");
    println!("SESSION CODE:");
    println!();
    println!("  {encoded}");
    println!();
    println!("Share this code with your peer.");
    if password.is_some() {
        println!("They need the same password to connect.");
    }
    println!("========================================");
    println!();

    if let Some(path) = std::env::var_os(CODE_FILE_ENV) {
        if let Err(e) = write_code_file(Path::new(&path), &encoded) {
            close_portmap(gathered.portmap.take()).await;
            return Err(e);
        }
    }

    // After the code is out: the publish happens in the background and must
    // not hold it back.
    let remote_rx = match signal_over_dht(dht, Role::Creator, &keys, &mut gathered, cancel).await? {
        Some(rx) => rx,
        None => {
            println!("{DHT_UNAVAILABLE}");
            closed_signal()
        }
    };

    run_session(
        Role::Creator,
        username,
        password,
        gathered,
        keys,
        vec![],
        remote_rx,
        cancel,
    )
    .await
}

async fn join_session(
    code: &str,
    username: &str,
    password: Option<&str>,
    cancel: &Cancel,
) -> Result<()> {
    check_username(username)?;
    // A bad code fails right away, before anything is opened on the router.
    let code = SessionCode::decode(code)?;
    let dht = start_dht();
    let mut gathered = gather_network(cancel).await?;
    let keys = SessionKeys::derive(&code.secret);

    // Without the DHT and without an address in the code there is no way to
    // find the creator: say so now instead of after the wait.
    let remote_rx = match signal_over_dht(dht, Role::Joiner, &keys, &mut gathered, cancel).await? {
        Some(rx) => rx,
        None => match without_dht(&code) {
            Ok(rx) => rx,
            Err(e) => {
                close_portmap(gathered.portmap.take()).await;
                return Err(e);
            }
        },
    };

    let initial_remote = code
        .direct
        .iter()
        .map(|&addr| Candidate {
            kind: infer_kind(addr),
            addr,
        })
        .collect();

    run_session(
        Role::Joiner,
        username,
        password,
        gathered,
        keys,
        initial_remote,
        remote_rx,
        cancel,
    )
    .await
}

/// Connects to the peer, runs the chat and releases the router port on every
/// way out.
// One over the lint's limit; the signature is fixed by the plan, plus `cancel`.
#[allow(clippy::too_many_arguments)]
async fn run_session(
    role: Role,
    username: &str,
    password: Option<&str>,
    gathered: Gathered,
    keys: SessionKeys,
    initial_remote: Vec<Candidate>,
    remote_rx: mpsc::Receiver<PeerInfo>,
    cancel: &Cancel,
) -> Result<()> {
    let Gathered {
        sockets,
        portmap,
        summary,
        ..
    } = gathered;

    // Argon2 is slow on purpose: derive the key once.
    let psk = derive_psk(&keys, password.unwrap_or(""));
    let args = ConnectArgs {
        role,
        keys: &keys,
        psk,
        username,
        initial_remote,
        timeouts: Timeouts::default(),
    };

    match role {
        Role::Creator => println!("Waiting for your peer to join... (Ctrl-C to cancel)"),
        Role::Joiner => println!("Connecting to your peer... (Ctrl-C to cancel)"),
    }

    // A Ctrl-C that came earlier (while gathering, or during the Argon2 above)
    // is seen at once.
    let connected = match cancel.run(connect(sockets, args, remote_rx)).await {
        Ok(connected) => connected,
        Err(cancelled) => {
            close_portmap(portmap).await;
            return Err(cancelled.into());
        }
    };

    let result = match connected {
        Ok(conn) => {
            println!("Connected to {} via {}", conn.peer_username, conn.path);
            println!(
                "Session fingerprint: {} (should match your peer's)",
                conn.fingerprint
            );
            if exit_on_connect() {
                println!("CONNECTED via {}", conn.path);
                Ok(())
            } else {
                run_chat(username, conn).await
            }
        }
        Err(ConnectError::NoPath { remote }) => {
            Err(anyhow!(doctor::explain_no_path(&summary, remote.as_ref())))
        }
        Err(e) => Err(e.into()),
    };

    close_portmap(portmap).await;
    println!("\nSession ended.");
    result
}

/// Runs the terminal chat off the async workers: it blocks until the user
/// leaves, and the router mapping is renewed by tasks on those workers.
async fn run_chat(username: &str, conn: Connection) -> Result<()> {
    let mut chat = P2PChat::new(username.to_string(), conn);
    tokio::task::spawn_blocking(move || chat.run()).await??;
    Ok(())
}

async fn close_portmap(portmap: Option<PortMap>) {
    if let Some(portmap) = portmap {
        portmap.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keys::SessionSecret;

    fn code(direct: &[&str]) -> SessionCode {
        SessionCode {
            secret: SessionSecret([1; 16]),
            direct: direct.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn code_file_holds_the_code_and_leaves_nothing_else_behind() {
        let dir = std::env::temp_dir().join(format!("whisper-code-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("code");

        write_code_file(&path, "first").unwrap();
        write_code_file(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        // A directory that does not exist is an error, not a silent skip.
        assert!(write_code_file(&dir.join("missing").join("code"), "x").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn join_without_dht_needs_a_direct_address() {
        let e = without_dht(&code(&[])).unwrap_err();
        assert_eq!(
            e.to_string(),
            "The DHT is unreachable and this code has no direct address, so the other peer cannot be found. Check that this network allows UDP traffic."
        );
        assert!(without_dht(&code(&["189.40.12.34:5000"])).is_ok());
    }
}
