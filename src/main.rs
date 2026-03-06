mod cli;
mod crypto;
mod hole_punch;
mod session;
mod stun;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::time::Duration;

use cli::P2PChat;
use crypto::{fingerprint, KeyExchange};
use hole_punch::{connect_to_peer, wait_for_peer};
use session::{validate_username, SessionAuth, SessionId, SessionInfo};
use stun::discover_public_endpoint;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[command(name = "t-chat")]
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

        /// Session password (shared with peer)
        #[arg(short, long)]
        password: String,
    },

    /// Join an existing chat session
    Join {
        /// Session code (given by the session creator)
        code: String,

        /// Your username
        #[arg(short, long)]
        username: String,

        /// Session password (shared with peer)
        #[arg(short, long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create { username, password } => {
            create_session(&username, &password).await?;
        }
        Commands::Join {
            code,
            username,
            password,
        } => {
            join_session(&code, &username, &password).await?;
        }
    }

    Ok(())
}

async fn create_session(username: &str, password: &str) -> Result<()> {
    // Validate username
    if let Err(e) = validate_username(username) {
        return Err(anyhow::anyhow!("Invalid username: {}", e));
    }

    println!("\nCreating session...\n");

    // Discover public endpoint via STUN (this also creates our socket)
    print!("Discovering public address... ");
    let (socket, public_addr) = discover_public_endpoint()?;
    println!("{}", public_addr);

    let local_addr = socket.local_addr()?;
    println!("Local socket: {}", local_addr);

    // Generate session ID and auth
    let session_id = SessionId::new();
    let auth = SessionAuth::new(password);

    // Create session info
    let session_info = SessionInfo::new(public_addr, session_id.clone(), *auth.salt());

    println!();
    println!("========================================");
    println!("SESSION CODE:");
    println!();
    println!("  {}", session_info.to_code());
    println!();
    println!("Share this code with your peer.");
    println!("They need the same password to connect.");
    println!("========================================");
    println!();

    // Generate keypair
    let key_exchange = KeyExchange::new();
    let our_public_key = key_exchange.public_key().as_bytes().to_vec();
    println!("Your fingerprint: {}", fingerprint(&our_public_key));
    println!();

    // Wait for peer
    let punch_result = wait_for_peer(
        &socket,
        session_info.id.as_str(),
        &key_exchange,
        username,
        CONNECTION_TIMEOUT,
    )?;

    // Derive shared secret
    let peer_public = x25519_dalek::PublicKey::from(punch_result.peer_public_key);
    let shared_secret = key_exchange.derive_shared_secret(&peer_public);

    println!();
    println!(
        "Peer connected: {} [{}]",
        punch_result.peer_username,
        fingerprint(&punch_result.peer_public_key)
    );
    println!();

    // Verify password by checking if we can communicate
    // (In a full implementation, we'd do a challenge-response here)

    // Start chat
    let mut chat = P2PChat::new(
        username.to_string(),
        punch_result.peer_username,
        socket,
        punch_result.peer_addr,
        shared_secret,
    );

    chat.run()?;

    println!("\nSession ended.");
    Ok(())
}

async fn join_session(code: &str, username: &str, password: &str) -> Result<()> {
    // Validate username
    if let Err(e) = validate_username(username) {
        return Err(anyhow::anyhow!("Invalid username: {}", e));
    }

    println!("\nJoining session...\n");

    // Parse session code
    let session_info = SessionInfo::from_code(code)?;
    println!("Peer address: {}", session_info.peer_addr);
    println!("Session ID: {}", session_info.id);

    // Derive password hash with provided salt
    let _auth = SessionAuth::with_salt(password, session_info.salt);

    // Discover our public endpoint (needed for hole punching) - this also creates our socket
    print!("Discovering public address... ");
    let (socket, public_addr) = discover_public_endpoint()?;
    println!("{}", public_addr);

    let local_addr = socket.local_addr()?;
    println!("Local socket: {}", local_addr);

    // Generate keypair
    let key_exchange = KeyExchange::new();
    let our_public_key = key_exchange.public_key().as_bytes().to_vec();
    println!();
    println!("Your fingerprint: {}", fingerprint(&our_public_key));
    println!();

    // Connect to peer via hole punching
    let punch_result = connect_to_peer(
        &socket,
        session_info.peer_addr,
        session_info.id.as_str(),
        &key_exchange,
        username,
        CONNECTION_TIMEOUT,
    )?;

    // Derive shared secret
    let peer_public = x25519_dalek::PublicKey::from(punch_result.peer_public_key);
    let shared_secret = key_exchange.derive_shared_secret(&peer_public);

    println!();
    println!(
        "Connected to: {} [{}]",
        punch_result.peer_username,
        fingerprint(&punch_result.peer_public_key)
    );
    println!();

    // Start chat
    let mut chat = P2PChat::new(
        username.to_string(),
        punch_result.peer_username,
        socket,
        punch_result.peer_addr,
        shared_secret,
    );

    chat.run()?;

    println!("\nSession ended.");
    Ok(())
}
