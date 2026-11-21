//! Full network gathering: sockets, local / mapped / reflexive candidates and
//! the NAT diagnosis. Combines the STUN probe, the router port mapping and the
//! interface scan into a single step shared by `whisper doctor` and sessions.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::candidates::{
    detect_cgnat, interface_addrs, is_global_v6, local_candidates, mapped_candidate, primary_v4,
    Candidate, CandidateKind,
};
use crate::portmap::{PortMap, ProbeFlags};
use crate::stun::{self, NatMapping};

/// How long the router gets to answer the protocol probe.
const PROBE_WAIT: Duration = Duration::from_secs(2);

/// Upper bound for the whole port-mapping step (probe plus waiting for the
/// external address).
const PORTMAP_WAIT: Duration = Duration::from_secs(4);

/// The UDP sockets a session talks through.
pub struct Sockets {
    pub v4: UdpSocket,
    pub v6: Option<UdpSocket>,
}

/// Binds the IPv4 socket and, when the machine has a global IPv6 address, an
/// IPv6 one (best effort: a failed IPv6 bind just means no IPv6 socket).
pub async fn bind_sockets(has_global_v6: bool) -> Result<Sockets> {
    let v4 = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind a UDP socket")?;
    let v6 = if has_global_v6 {
        UdpSocket::bind("[::]:0").await.ok()
    } else {
        None
    };
    Ok(Sockets { v4, v6 })
}

/// What this network allows, in short.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetSummary {
    /// A global IPv6 address with a socket to use it.
    pub ipv6: bool,
    /// The router mapped a public IPv4 port for us.
    pub mapped: bool,
    /// Behind carrier-grade NAT; `None` when there is not enough information.
    pub cgnat: Option<bool>,
    pub nat: NatMapping,
}

impl NetSummary {
    /// Whether a peer can reach us without us punching a hole first.
    pub fn can_host(&self) -> bool {
        self.ipv6 || self.mapped
    }
}

/// Everything learned about this machine's connectivity.
pub struct Gathered {
    pub sockets: Sockets,
    pub candidates: Vec<Candidate>,
    pub summary: NetSummary,
    /// The router mapping, kept open only when it produced a `Mapped`
    /// candidate. Callers must `close().await` it.
    pub portmap: Option<PortMap>,
    pub probe: Option<ProbeFlags>,
    pub router_ext: Option<SocketAddrV4>,
    pub stun_addr: Option<SocketAddr>,
    pub ipv6_addr: Option<Ipv6Addr>,
}

impl Gathered {
    /// The external port the router mapped for us.
    pub fn mapped_port(&self) -> Option<u16> {
        self.candidates
            .iter()
            .find(|c| c.kind == CandidateKind::Mapped)
            .map(|c| c.addr.port())
    }

    /// The IPv4 address STUN servers see us at.
    pub fn stun_ip(&self) -> Option<Ipv4Addr> {
        v4_ip(self.stun_addr)
    }
}

fn v4_ip(addr: Option<SocketAddr>) -> Option<Ipv4Addr> {
    match addr {
        Some(SocketAddr::V4(a)) => Some(*a.ip()),
        _ => None,
    }
}

/// Interface addresses with the default-route IPv4 first, then the rest in
/// their original order, without repeats. `local_candidates` keeps only a few
/// `Lan` entries, and this keeps a Docker/VM bridge from taking their place.
fn ordered_addrs(primary: Option<Ipv4Addr>, addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = primary.map(IpAddr::V4).into_iter().collect();
    for addr in addrs {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// Gathers everything: sockets, router mapping, STUN reflexive address and NAT
/// type, local interface addresses and the CGNAT verdict.
pub async fn gather() -> Result<Gathered> {
    let primary = primary_v4();
    let addrs = ordered_addrs(primary, interface_addrs());
    let has_global_v6 = addrs
        .iter()
        .any(|a| matches!(a, IpAddr::V6(ip) if is_global_v6(ip)));
    let sockets = bind_sockets(has_global_v6).await?;
    let v4_port = sockets.v4.local_addr()?.port();
    let v6_port = match &sockets.v6 {
        Some(s) => Some(s.local_addr()?.port()),
        None => None,
    };

    let pm = PortMap::start(v4_port);
    let ((stun_addr, nat), (probe, router_ext)) =
        tokio::join!(stun::probe_nat(&sockets.v4), map_port(&pm));

    let mut candidates = local_candidates(&addrs, v4_port, v6_port);
    let ipv6_addr = candidates.iter().find_map(|c| match c.addr {
        SocketAddr::V6(a) if c.kind == CandidateKind::Ipv6 => Some(*a.ip()),
        _ => None,
    });
    let mapped = mapped_candidate(router_ext);
    candidates.extend(mapped);
    if let Some(addr) = stun_addr {
        // A reflexive address equal to one we already have adds nothing.
        if !candidates.iter().any(|c| c.addr == addr) {
            candidates.push(Candidate {
                kind: CandidateKind::Reflexive,
                addr,
            });
        }
    }

    let summary = NetSummary {
        ipv6: ipv6_addr.is_some(),
        mapped: mapped.is_some(),
        cgnat: detect_cgnat(primary, router_ext.map(|a| *a.ip()), v4_ip(stun_addr)),
        nat,
    };

    // A mapping that is not usable (e.g. the router itself is behind another
    // NAT) must not be left open on the router.
    let portmap = if mapped.is_some() {
        Some(pm)
    } else {
        pm.close().await;
        None
    };

    Ok(Gathered {
        sockets,
        candidates,
        summary,
        portmap,
        probe,
        router_ext,
        stun_addr,
        ipv6_addr,
    })
}

/// Probes the router's port mapping protocols, then waits for the external
/// address, all within `PORTMAP_WAIT`.
async fn map_port(pm: &PortMap) -> (Option<ProbeFlags>, Option<SocketAddrV4>) {
    let started = Instant::now();
    let probe = pm.probe(PROBE_WAIT).await;
    // The first mapping attempt only uses UPnP; PCP and NAT-PMP are tried only
    // once a probe has recorded them, so retry if the router speaks either.
    let already_mapped = pm.wait_external(Duration::ZERO).await.is_some();
    if !already_mapped && probe.is_some_and(|p| p.pcp || p.nat_pmp) {
        pm.procure();
    }
    let ext = pm
        .wait_external(PORTMAP_WAIT.saturating_sub(started.elapsed()))
        .await;
    (probe, ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_host_with_ipv6_or_mapping() {
        let s = |ipv6, mapped| NetSummary {
            ipv6,
            mapped,
            cgnat: None,
            nat: NatMapping::Unknown,
        };
        assert!(s(true, false).can_host());
        assert!(s(false, true).can_host());
        assert!(!s(false, false).can_host());
    }

    #[test]
    fn primary_address_goes_first_and_duplicates_are_dropped() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let all = vec![
            ip("172.17.0.1"),
            ip("192.168.1.10"),
            ip("fe80::1"),
            ip("172.17.0.1"),
        ];
        assert_eq!(
            ordered_addrs(Some("192.168.1.10".parse().unwrap()), all.clone()),
            vec![ip("192.168.1.10"), ip("172.17.0.1"), ip("fe80::1")]
        );
        assert_eq!(
            ordered_addrs(None, all),
            vec![ip("172.17.0.1"), ip("192.168.1.10"), ip("fe80::1")]
        );
    }

    #[test]
    fn bridge_addresses_do_not_take_the_lan_slots_of_the_primary() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        // Docker and VM bridges are listed before the real interface.
        let all = vec![ip("172.17.0.1"), ip("192.168.56.1"), ip("192.168.1.10")];
        let addrs = ordered_addrs(Some("192.168.1.10".parse().unwrap()), all);
        let lan: Vec<_> = local_candidates(&addrs, 4000, None)
            .into_iter()
            .map(|c| c.addr.ip())
            .collect();
        assert_eq!(lan, vec![ip("192.168.1.10"), ip("172.17.0.1")]);
    }
}
