//! Router port mapping (UPnP / NAT-PMP / PCP) via the `portmapper` crate.
//!
//! Opens a UDP port on the user's router so peers outside the LAN can reach
//! us directly, and closes it again on exit. The mapping lease (2 hours) is
//! fixed by the crate, which is why it must be released explicitly.

use portmapper::Client;
use std::net::SocketAddrV4;
use std::num::NonZeroU16;
use std::time::Duration;

/// How long `close` waits for the router mapping to be dropped.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

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
/// `close` (or, best effort, when dropped).
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
            client.update_local_port(port);
            client.procure_mapping();
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

    /// Releases the router mapping, waiting up to 2 seconds for it to go away.
    pub async fn close(self) {
        self.client.deactivate();
        let mut rx = self.client.watch_external_address();
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, rx.wait_for(|addr| addr.is_none())).await;
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

    #[tokio::test]
    async fn close_completes_within_three_seconds() {
        let pm = PortMap::start(40_123);
        let _ = pm.wait_external(Duration::from_millis(500)).await;
        let t = std::time::Instant::now();
        pm.close().await;
        assert!(t.elapsed() < Duration::from_secs(3));
    }
}
