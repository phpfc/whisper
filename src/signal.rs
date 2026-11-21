//! Rendezvous signaling over the public Mainline DHT.

/// Starts a DHT client node that bootstraps from the default public nodes.
pub fn public_dht() -> std::io::Result<mainline::async_dht::AsyncDht> {
    Ok(mainline::Dht::client()?.as_async())
}
