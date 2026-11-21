//! A private Mainline DHT for the NAT lab.
//!
//! Starts `n` DHT nodes in server mode on `ip`, prints their addresses as one
//! comma-separated line (the format `WHISPER_DHT_BOOTSTRAP` takes) and keeps
//! running until it is killed.
//!
//! ```text
//! cargo run --example dht_bootstrap -- <ip> <n>
//! WHISPER_DHT_BOOTSTRAP=<that line> whisper create -u alice
//! ```

use std::net::Ipv4Addr;

use anyhow::{ensure, Context, Result};
use mainline::Testnet;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: dht_bootstrap <ip> <n>";
    let ip: Ipv4Addr = args
        .next()
        .context(usage)?
        .parse()
        .context("the first argument must be an IPv4 address")?;
    let count: usize = args
        .next()
        .context(usage)?
        .parse()
        .context("the second argument must be a number of nodes")?;
    ensure!(count > 0, "need at least one node");

    // Dropping the testnet would shut the nodes down: it lives until the
    // process is killed.
    let testnet = Testnet::builder(count)
        .bind_address(ip)
        .build()
        .with_context(|| format!("could not start the nodes on {ip}"))?;
    println!("{}", testnet.bootstrap.join(","));

    loop {
        std::thread::park();
    }
}
