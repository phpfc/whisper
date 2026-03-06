use std::time::Duration;
use tokio::net::TcpStream;

/// Lista de relays públicos conhecidos
///
/// Estes são servidores mantidos pela comunidade que qualquer um pode usar.
/// Novos relays podem ser descobertos dinamicamente.
const KNOWN_PUBLIC_RELAYS: &[&str] = &[
    // Serviços públicos gratuitos (exemplos):
    // "tchat-relay.onrender.com:8080",
    // "tchat-relay.railway.app:8080",
    // "tchat-relay.fly.dev:8080",

    // Para desenvolvimento e teste local
    "127.0.0.1:8080",
    "localhost:8080",
];

/// Verifica se um relay está online e respondendo
pub async fn check_relay_health(addr: &str) -> bool {
    let timeout = Duration::from_secs(3);

    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => true,
        _ => false,
    }
}

/// Encontra o melhor relay disponível testando todos
pub async fn find_best_relay() -> Option<String> {
    println!("🔍 Searching for available relays...");

    for relay in KNOWN_PUBLIC_RELAYS {
        print!("  Trying {}... ", relay);
        if check_relay_health(relay).await {
            println!("✓ Online");
            return Some(relay.to_string());
        } else {
            println!("✗ Offline");
        }
    }

    println!("⚠️  No public relays available");
    None
}

/// Retorna relay padrão (primeiro da lista)
pub fn get_default_relay() -> String {
    KNOWN_PUBLIC_RELAYS[0].to_string()
}

/// Testa múltiplos relays em paralelo e retorna o primeiro que responder
pub async fn find_fastest_relay() -> Option<String> {
    use tokio::sync::mpsc;

    let (tx, mut rx) = mpsc::unbounded_channel();

    // Testa todos os relays em paralelo
    for relay in KNOWN_PUBLIC_RELAYS {
        let relay = relay.to_string();
        let tx = tx.clone();

        tokio::spawn(async move {
            if check_relay_health(&relay).await {
                tx.send(relay).ok();
            }
        });
    }

    drop(tx);

    // Retorna o primeiro que responder (mais rápido)
    rx.recv().await
}
