//! A minimal STUN server for the NAT lab.
//!
//! Answers every Binding Request with an XOR-MAPPED-ADDRESS holding the
//! address the request came from, which is all `whisper` asks of a STUN
//! server. IPv4 only.
//!
//! ```text
//! cargo run --example stun_responder -- <ip:port>
//! WHISPER_STUN_SERVERS=<ip:port>,<ip:port> whisper doctor
//! ```
//!
//! The crate has no library target, so the STUN code is included from `src/`
//! rather than copied. `stun.rs` and `util.rs` must therefore not refer to
//! the rest of the crate (`util.rs` is here because `stun.rs` uses it).

#[allow(dead_code)]
#[path = "../src/stun.rs"]
mod stun;
#[allow(dead_code)]
#[path = "../src/util.rs"]
mod util;

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

/// The transaction id of `datagram` if it is a STUN Binding Request.
fn binding_request_txid(datagram: &[u8]) -> Option<[u8; 12]> {
    let is_request = datagram.len() >= 20
        && datagram[0..2] == [0x00, 0x01]
        && datagram[4..8] == [0x21, 0x12, 0xA4, 0x42];
    is_request.then(|| datagram[8..20].try_into().expect("12 bytes"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let bind: SocketAddr = std::env::args()
        .nth(1)
        .context("usage: stun_responder <ip:port>")?
        .parse()
        .context("the address must look like 10.0.0.2:3478")?;
    let socket = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("could not bind {bind}"))?;
    println!("STUN responder listening on {}", socket.local_addr()?);

    let mut buf = [0u8; 1500];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) if util::is_transient(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        let (Some(txid), SocketAddr::V4(from)) = (binding_request_txid(&buf[..len]), from) else {
            continue;
        };
        // One unreachable sender must not stop the server.
        let response = stun::build_binding_response(&txid, from);
        if let Err(e) = socket.send_to(&response, from).await {
            eprintln!("could not answer {from}: {e}");
        }
    }
}
