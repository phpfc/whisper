//! Router port mapping (UPnP / NAT-PMP / PCP) via the `portmapper` crate.
//!
//! Opens a UDP port on the user's router so peers outside the LAN can reach
//! us directly, and closes it again on exit. The mapping lease (2 hours) is
//! fixed by the crate, which is why it must be released explicitly.

use portmapper::Client;
use std::net::SocketAddrV4;
use std::num::NonZeroU16;
use std::time::Duration;
use tokio::time::{timeout_at, Instant};

/// Upper bound for the whole of `close` (kept under 3 s).
const CLOSE_TIMEOUT: Duration = Duration::from_millis(2_500);

/// Which port mapping protocols the router answered to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeFlags {
    pub upnp: bool,
    pub nat_pmp: bool,
    pub pcp: bool,
}

/// A router port mapping for one local UDP port.
///
/// The mapping is requested in the background by `start` and released by
/// `close`. Callers must call `close().await` on every exit path: dropping
/// only queues a release that the crate's background task is usually aborted
/// before it can run.
pub struct PortMap {
    client: Client,
}

impl PortMap {
    /// Starts asking the router to forward an external UDP port to
    /// `local_port`. Returns immediately; use `wait_external` for the result.
    /// A `local_port` of 0 requests no mapping.
    pub fn start(local_port: u16) -> Self {
        let client = Client::default();
        if let Some(port) = NonZeroU16::new(local_port) {
            // A new local port already starts the mapping attempt inside the
            // crate, so no separate `procure_mapping()` (it would restart it).
            client.update_local_port(port);
        }
        Self { client }
    }

    /// Waits up to `timeout` for the router to report our external address.
    /// `None` if no mapping was obtained in time.
    pub async fn wait_external(&self, timeout: Duration) -> Option<SocketAddrV4> {
        let mut rx = self.client.watch_external_address();
        let current = tokio::time::timeout(timeout, rx.wait_for(|addr| addr.is_some()))
            .await
            .ok()?
            .ok()?;
        *current
    }

    /// Asks the router which port mapping protocols it supports. `None` if it
    /// did not answer within `timeout` (or there is no gateway to ask).
    pub async fn probe(&self, timeout: Duration) -> Option<ProbeFlags> {
        let output = tokio::time::timeout(timeout, self.client.probe())
            .await
            .ok()?
            .ok()?
            .ok()?;
        Some(ProbeFlags {
            upnp: output.upnp,
            nat_pmp: output.nat_pmp,
            pcp: output.pcp,
        })
    }

    /// Retries the mapping now that a probe has recorded which protocols the
    /// router speaks (the crate's first attempt after `start` is UPnP-only).
    pub fn procure(&self) {
        self.client.procure_mapping();
    }

    /// Releases the router mapping and waits (bounded by `CLOSE_TIMEOUT`) for
    /// the release request to be done.
    pub async fn close(self) {
        let deadline = Instant::now() + CLOSE_TIMEOUT;
        let mut rx = self.client.watch_external_address();
        let had_mapping = rx.borrow().is_some();
        self.client.deactivate();
        let _ = timeout_at(deadline, rx.wait_for(|addr| addr.is_none())).await;
        if had_mapping {
            self.wait_release_done(deadline).await;
        }
    }

    /// Returns once the crate's service has finished releasing the mapping
    /// (or at `deadline`).
    ///
    /// The watcher turns `None` *before* the release request is sent (UPnP
    /// even awaits the router's HTTP reply), and dropping the `Client` aborts
    /// the service, which would cancel that request and leave the port open
    /// until its 2 h lease expires. The service handles messages one at a
    /// time and awaits the release inline, so a probe queued after
    /// `deactivate` is only answered once the release has finished.
    async fn wait_release_done(&self, deadline: Instant) {
        let _ = timeout_at(deadline, self.client.probe()).await;
    }
}

impl Drop for PortMap {
    /// Best effort for when nobody called `close`.
    fn drop(&mut self) {
        self.client.deactivate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both tests ask the router of the machine running them for a real
    // mapping, which `cargo test` must not do behind the developer's back.
    // Run them with `cargo test -- --ignored portmap`.
    #[tokio::test]
    #[ignore = "talks to the router of the machine running the tests"]
    async fn close_completes_within_three_seconds() {
        let pm = PortMap::start(40_123);
        let _ = pm.wait_external(Duration::from_millis(500)).await;
        let t = std::time::Instant::now();
        pm.close().await;
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    #[ignore = "talks to the router of the machine running the tests"]
    async fn release_barrier_is_answered_before_the_deadline() {
        let pm = PortMap::start(40_124);
        pm.client.deactivate();
        let t = std::time::Instant::now();
        pm.wait_release_done(Instant::now() + CLOSE_TIMEOUT).await;
        assert!(t.elapsed() < CLOSE_TIMEOUT);
    }
}
