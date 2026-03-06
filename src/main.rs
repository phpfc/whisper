mod cli;
mod crypto;
mod p2p;
mod session;
mod relay;
mod stun;
mod upnp;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cli::ChatClient;
use p2p::Server;
use session::{SessionId, SessionInfo};
use relay::find_best_relay;
use stun::discover_public_address;
use upnp::open_port;

#[derive(Parser)]
#[command(name = "t-chat")]
#[command(about = "A simple, secure, and private P2P chat CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        addr: String,
    },

    Create {
        #[arg(short, long)]
        username: String,

        #[arg(short, long)]
        password: String,

        #[arg(short, long)]
        server: Option<String>,
    },

    Join {
        #[arg(short, long)]
        session: String,

        #[arg(short, long)]
        username: String,

        #[arg(short, long)]
        password: String,

        #[arg(short = 'S', long)]
        server: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { addr } => {
            let server = Server::new();
            println!("Starting t-chat server on {}...", addr);
            server.run(&addr).await?;
        }
        Commands::Create {
            username,
            password,
            server,
        } => {
            let session_id = SessionId::new();

            println!("\n🚀 Creating new session...");

            // Determina endereços: conexão (local) e compartilhamento (público)
            let (connection_addr, share_addr) = match server {
                Some(s) => {
                    println!("📡 Connecting to relay: {}", s);
                    // Servidor especificado: usa o mesmo para conexão e compartilhamento
                    (s.clone(), s)
                }
                None => {
                    // Tenta buscar relay público primeiro
                    print!("🔍 Looking for public relays... ");
                    match find_best_relay().await {
                        Some(relay) => {
                            println!("Found!");
                            // Relay público: usa o mesmo para conexão e compartilhamento
                            (relay.clone(), relay)
                        }
                        None => {
                            // Nenhum relay disponível - vira servidor!
                            println!("None found.");
                            println!("💡 Starting embedded relay server...");

                            // Descobre IP público via STUN
                            print!("🌐 Discovering public IP via STUN... ");
                            let public_addr = match discover_public_address() {
                                Ok(addr) => {
                                    println!("{}", addr.ip());
                                    format!("{}:8080", addr.ip())
                                }
                                Err(_) => {
                                    println!("Failed (using local)");
                                    "127.0.0.1:8080".to_string()
                                }
                            };

                            let server = Server::new();
                            let local_addr = "127.0.0.1:8080".to_string();

                            // Tenta abrir porta via UPnP
                            print!("🔓 Opening port 8080 via UPnP... ");
                            match open_port(8080).await {
                                Ok(_) => println!("Success!"),
                                Err(_) => println!("Failed (router may not support UPnP)"),
                            }

                            // Roda servidor em background
                            tokio::spawn(async move {
                                if let Err(e) = server.run("0.0.0.0:8080").await {
                                    eprintln!("Server error: {}", e);
                                }
                            });

                            // Aguarda servidor iniciar com retry
                            print!("⏳ Waiting for relay to start... ");
                            let mut retries = 0;
                            loop {
                                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                                if relay::check_relay_health(&local_addr).await {
                                    println!("Ready!");
                                    break;
                                }
                                retries += 1;
                                if retries > 10 {
                                    return Err(anyhow::anyhow!("Failed to start embedded server"));
                                }
                            }

                            println!("✓ Relay running, accessible at: {}", public_addr);

                            // Alice conecta localmente, mas compartilha endereço público
                            (local_addr, public_addr)
                        }
                    }
                }
            };

            // Cria SessionInfo com relay público para compartilhar
            let session_info = SessionInfo::new(session_id.clone(), share_addr);

            println!("\n📋 Session Code: {}", session_info);
            println!("📤 Share this FULL code with others to let them join!\n");

            let mut client = ChatClient::new(username, session_id, connection_addr);
            client.connect(&password).await?;
        }
        Commands::Join {
            session,
            username,
            password,
            server,
        } => {
            println!("\n📥 Joining session...");

            // Parse SessionInfo (pode ter formato: id@relay ou apenas id)
            let session_info = SessionInfo::from_string(&session)?;

            let server_addr = match server {
                Some(s) => {
                    println!("📡 Using specified relay: {}", s);
                    s
                }
                None => {
                    // Usa o relay do session code
                    println!("📡 Connecting to relay: {}", session_info.relay_addr);
                    session_info.relay_addr.clone()
                }
            };

            println!("🔑 Session ID: {}", session_info.id);

            let mut client = ChatClient::new(username, session_info.id, server_addr);
            client.connect(&password).await?;
        }
    }

    Ok(())
}
