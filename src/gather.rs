//! Full network gathering: sockets, local / mapped / reflexive candidates and
//! the NAT diagnosis. Combines the STUN probe, the router port mapping and the
//! interface scan into a single step shared by `whisper doctor` and sessions.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::cancel::{Cancel, Cancelled};
use crate::candidates::{
    detect_cgnat, interface_addrs, is_global_v6, local_candidates, mapped_candidate, preferred_v6,
    primary_v4, Candidate, CandidateKind,
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
///
/// The IPv6 socket goes on `preferred_v6`, the address the OS would send
/// from, so that what we send leaves from the address we advertise. Left on
/// `[::]` the OS picks the source per packet, often a temporary privacy
/// address the peer never heard of, and its firewall drops the packet.
pub async fn bind_sockets(has_global_v6: bool, preferred_v6: Option<Ipv6Addr>) -> Result<Sockets> {
    let v4 = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind a UDP socket")?;
    let mut v6 = None;
    if has_global_v6 {
        for addr in v6_bind_order(preferred_v6) {
            if let Ok(socket) = UdpSocket::bind(addr).await {
                v6 = Some(socket);
                break;
            }
        }
    }
    Ok(Sockets { v4, v6 })
}

/// Where the IPv6 socket is bound, in order of preference: the preferred
/// source address if there is one, else (or if that fails) any address.
fn v6_bind_order(preferred: Option<Ipv6Addr>) -> Vec<SocketAddr> {
    let any = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0);
    preferred
        .map(|ip| SocketAddr::new(ip.into(), 0))
        .into_iter()
        .chain([any])
        .collect()
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

/// Interface addresses with the default-route IPv4 and IPv6 first, then the
/// rest in their original order, without repeats. `local_candidates` keeps
/// only a few entries of each kind, and this keeps a Docker/VM bridge from
/// taking their place.
fn ordered_addrs(
    primary_v4: Option<Ipv4Addr>,
    preferred_v6: Option<Ipv6Addr>,
    addrs: Vec<IpAddr>,
) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = primary_v4.map(IpAddr::V4).into_iter().collect();
    out.extend(preferred_v6.map(IpAddr::V6));
    for addr in addrs {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// Gathers everything: sockets, router mapping, STUN reflexive address and NAT
/// type, local interface addresses and the CGNAT verdict.
///
/// Ctrl-C ends it early with a [`Cancelled`] error. A router mapping that was
/// already requested is released first, so nothing stays open on the router.
pub async fn gather(cancel: &Cancel) -> Result<Gathered> {
    let primary = primary_v4();
    let preferred = preferred_v6();
    let addrs = ordered_addrs(primary, preferred, interface_addrs());
    let has_global_v6 = addrs
        .iter()
        .any(|a| matches!(a, IpAddr::V6(ip) if is_global_v6(ip)));
    let sockets = bind_sockets(has_global_v6, preferred).await?;
    let v4_port = sockets.v4.local_addr()?.port();
    let v6_local = match &sockets.v6 {
        Some(s) => Some(s.local_addr()?),
        None => None,
    };

    // Nothing is open on the router yet, so there is nothing to release.
    if cancel.is_cancelled() {
        return Err(Cancelled.into());
    }

    let (pm, ((stun_addr, nat), (probe, router_ext))) = guarded(
        PortMap::start(v4_port),
        cancel,
        async |pm| tokio::join!(stun::probe_nat(&sockets.v4), map_port(pm)),
        PortMap::close,
    )
    .await?;

    let mut candidates = local_candidates(&addrs, v4_port, v6_local);
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

/// Runs `work` with `resource`. If Ctrl-C comes first, `work` is dropped,
/// `release` runs to the end and the result is [`Cancelled`]; otherwise the
/// caller gets the resource back with the result and stays in charge of it.
async fn guarded<P, T>(
    resource: P,
    cancel: &Cancel,
    work: impl AsyncFnOnce(&P) -> T,
    release: impl AsyncFnOnce(P),
) -> Result<(P, T), Cancelled> {
    match cancel.run(work(&resource)).await {
        Ok(result) => Ok((resource, result)),
        Err(cancelled) => {
            release(resource).await;
            Err(cancelled)
        }
    }
}

/// The probe got an answer and the router speaks none of the protocols, so no
/// mapping will ever appear. A probe that got no answer proves nothing.
fn router_offers_nothing(probe: Option<ProbeFlags>) -> bool {
    probe.is_some_and(|p| !(p.upnp || p.nat_pmp || p.pcp))
}

/// PCP and NAT-PMP are only used once a probe has recorded them (the crate's
/// first attempt after `start` is UPnP-only), so the mapping must be retried.
fn needs_procure(probe: Option<ProbeFlags>) -> bool {
    probe.is_some_and(|p| p.pcp || p.nat_pmp)
}

/// Probes the router's port mapping protocols, then waits for the external
/// address, all within `PORTMAP_WAIT`. Returns right away when the router
/// offers no protocol.
async fn map_port(pm: &PortMap) -> (Option<ProbeFlags>, Option<SocketAddrV4>) {
    let started = Instant::now();
    let probe = pm.probe(PROBE_WAIT).await;
    let current = pm.wait_external(Duration::ZERO).await;
    if current.is_some() {
        return (probe, current);
    }
    if router_offers_nothing(probe) {
        return (probe, None);
    }
    if needs_procure(probe) {
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
    fn port_mapping_wait_depends_on_what_the_probe_found() {
        let flags = |upnp, nat_pmp, pcp| Some(ProbeFlags { upnp, nat_pmp, pcp });

        // No protocol at all: nothing to wait for.
        assert!(router_offers_nothing(flags(false, false, false)));
        // Any protocol, or no answer from the probe: keep waiting.
        assert!(!router_offers_nothing(flags(true, false, false)));
        assert!(!router_offers_nothing(flags(false, true, false)));
        assert!(!router_offers_nothing(flags(false, false, true)));
        assert!(!router_offers_nothing(None));

        // Only PCP / NAT-PMP need the mapping retried after the probe.
        assert!(needs_procure(flags(false, true, false)));
        assert!(needs_procure(flags(false, false, true)));
        assert!(!needs_procure(flags(true, false, false)));
        assert!(!needs_procure(flags(false, false, false)));
        assert!(!needs_procure(None));
    }

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
            ordered_addrs(Some("192.168.1.10".parse().unwrap()), None, all.clone()),
            vec![ip("192.168.1.10"), ip("172.17.0.1"), ip("fe80::1")]
        );
        assert_eq!(
            ordered_addrs(None, None, all),
            vec![ip("172.17.0.1"), ip("192.168.1.10"), ip("fe80::1")]
        );
    }

    #[test]
    fn the_preferred_ipv6_address_goes_first_among_the_ipv6_ones() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let all = vec![ip("2804::1"), ip("192.168.1.10"), ip("2804::2")];
        assert_eq!(
            ordered_addrs(
                Some("192.168.1.10".parse().unwrap()),
                Some("2804::2".parse().unwrap()),
                all
            ),
            vec![ip("192.168.1.10"), ip("2804::2"), ip("2804::1")]
        );
    }

    #[test]
    fn the_ipv6_socket_tries_the_preferred_address_then_any() {
        let pref: Ipv6Addr = "2804::2".parse().unwrap();
        assert_eq!(
            v6_bind_order(Some(pref)),
            vec![SocketAddr::new(pref.into(), 0), "[::]:0".parse().unwrap()]
        );
        assert_eq!(v6_bind_order(None), vec!["[::]:0".parse().unwrap()]);
    }

    #[test]
    fn bridge_addresses_do_not_take_the_lan_slots_of_the_primary() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        // Docker and VM bridges are listed before the real interface.
        let all = vec![ip("172.17.0.1"), ip("192.168.56.1"), ip("192.168.1.10")];
        let addrs = ordered_addrs(Some("192.168.1.10".parse().unwrap()), None, all);
        let lan: Vec<_> = local_candidates(&addrs, 4000, None)
            .into_iter()
            .map(|c| c.addr.ip())
            .collect();
        assert_eq!(lan, vec![ip("192.168.1.10"), ip("172.17.0.1")]);
    }

    #[tokio::test]
    async fn cancelling_releases_the_resource_before_reporting_cancelled() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let (tx, cancel) = Cancel::channel();
        let released = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&released);

        let press = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tx.send(true).unwrap();
        };
        let guard = guarded(
            "mapping",
            &cancel,
            async |_| std::future::pending::<()>().await,
            async |resource| {
                assert_eq!(resource, "mapping");
                // Release takes a while, as `PortMap::close` does.
                tokio::time::sleep(Duration::from_millis(30)).await;
                flag.store(true, Ordering::SeqCst);
            },
        );
        let (result, ()) = tokio::join!(guard, press);

        assert!(result.is_err());
        // The release ran to the end before `guarded` returned.
        assert!(released.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn without_ctrl_c_the_resource_comes_back_for_the_caller() {
        let (_tx, cancel) = Cancel::channel();
        let (resource, result) = guarded(
            "mapping",
            &cancel,
            async |r| r.len(),
            async |_| panic!("nothing to release"),
        )
        .await
        .unwrap();
        assert_eq!((resource, result), ("mapping", 7));
    }

    #[tokio::test]
    async fn ctrl_c_before_the_mapping_is_requested_just_returns() {
        let (tx, cancel) = Cancel::channel();
        tx.send(true).unwrap();
        let started = std::time::Instant::now();
        let err = gather(&cancel)
            .await
            .err()
            .expect("gathering was cancelled");
        assert!(err.is::<Cancelled>());
        // No STUN round trips and no mapping to wait for.
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
