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
mod wire;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::sync::mpsc;

use cancel::{Cancel, Cancelled};
use candidates::{infer_kind, select_direct, Candidate};
use cli::P2PChat;
use code::SessionCode;
use connect::{connect, ConnectArgs, Connection, PeerInfo, Role, Timeouts};
use gather::{gather, Gathered};
use keys::{derive_psk, SessionKeys, SessionSecret};
use portmap::PortMap;
use session::validate_username;

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

/// A receiver that never yields: nobody signals us until the DHT is wired in.
fn closed_signal() -> mpsc::Receiver<PeerInfo> {
    let (_tx, rx) = mpsc::channel(1);
    rx
}

async fn create_session(username: &str, password: Option<&str>, cancel: &Cancel) -> Result<()> {
    check_username(username)?;
    let gathered = gather_network(cancel).await?;

    let secret = SessionSecret::generate();
    let code = SessionCode {
        secret,
        direct: select_direct(&gathered.candidates),
    };

    println!();
    println!("========================================");
    println!("SESSION CODE:");
    println!();
    println!("  {}", code.encode());
    println!();
    println!("Share this code with your peer.");
    if password.is_some() {
        println!("They need the same password to connect.");
    }
    println!("========================================");
    println!();

    run_session(
        Role::Creator,
        username,
        password,
        gathered,
        SessionKeys::derive(&secret),
        vec![],
        closed_signal(),
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
    let gathered = gather_network(cancel).await?;

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
        SessionKeys::derive(&code.secret),
        initial_remote,
        closed_signal(),
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
        sockets, portmap, ..
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
            run_chat(username, conn).await
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
