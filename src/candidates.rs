//! Connection candidates and address classification.
//!
//! Pure logic that turns local interface addresses and STUN/port-mapping
//! results into the candidate list shared with the peer, and picks which of
//! them go into the invite code.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};

/// At most this many `Lan` candidates are advertised.
const MAX_LAN: usize = 2;

/// At most this many `Ipv6` candidates are advertised.
const MAX_IPV6: usize = 3;

/// How a candidate address was learned. Also its path priority.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    /// Private IPv4 address on a local interface.
    Lan,
    /// Global IPv6 address on a local interface.
    Ipv6,
    /// Public address from a router port mapping (UPnP / NAT-PMP / PCP).
    Mapped,
    /// Public address reported by a STUN server.
    Reflexive,
    /// Source address of a probe we received from the peer.
    PeerReflexive,
}

impl CandidateKind {
    /// Higher is preferred: lan > ipv6 > mapped > reflexive > peer-reflexive.
    pub fn priority(self) -> u8 {
        match self {
            CandidateKind::Lan => 5,
            CandidateKind::Ipv6 => 4,
            CandidateKind::Mapped => 3,
            CandidateKind::Reflexive => 2,
            CandidateKind::PeerReflexive => 1,
        }
    }
}

impl fmt::Display for CandidateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CandidateKind::Lan => "lan",
            CandidateKind::Ipv6 => "ipv6",
            CandidateKind::Mapped => "mapped",
            CandidateKind::Reflexive => "reflexive",
            CandidateKind::PeerReflexive => "peer-reflexive",
        })
    }
}

/// An address the peer may be able to reach us at.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub addr: SocketAddr,
}

/// Coarse classification of an IPv4 address.
#[derive(Debug, PartialEq, Eq)]
pub enum V4Class {
    Public,
    /// RFC 1918 (10/8, 172.16/12, 192.168/16).
    Private,
    /// Carrier-grade NAT shared space, 100.64.0.0/10 (RFC 6598).
    Cgnat,
    Loopback,
    LinkLocal,
    Unspecified,
    /// Not reachable on the internet: "this network" (0/8), IETF protocol
    /// assignments (192.0.0.0/24, DS-Lite's 192.0.0.0/29 among them),
    /// benchmarking (198.18.0.0/15), multicast (224/4), the future-use block
    /// (240/4, broadcast included) and the documentation ranges.
    Reserved,
}

pub fn classify_v4(ip: Ipv4Addr) -> V4Class {
    let [a, b, c, _] = ip.octets();
    let reserved = a == 0
        || (a, b, c) == (192, 0, 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 224
        || [(192, 0, 2), (198, 51, 100), (203, 0, 113)].contains(&(a, b, c));
    if ip.is_unspecified() {
        V4Class::Unspecified
    } else if ip.is_loopback() {
        V4Class::Loopback
    } else if ip.is_link_local() {
        V4Class::LinkLocal
    } else if ip.is_private() {
        V4Class::Private
    } else if a == 100 && (64..=127).contains(&b) {
        V4Class::Cgnat
    } else if reserved {
        V4Class::Reserved
    } else {
        V4Class::Public
    }
}

/// True only for global unicast IPv6 (2000::/3).
pub fn is_global_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xe000 == 0x2000
}

/// Addresses of the local network interfaces, without loopback.
pub fn interface_addrs() -> Vec<IpAddr> {
    if_addrs::get_if_addrs()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .filter(|i| !i.is_loopback())
                .map(|i| i.ip())
                .collect()
        })
        .unwrap_or_default()
}

/// The IPv4 address the OS would use to reach the internet.
///
/// Connecting a UDP socket only picks a route; no packet is sent.
pub fn primary_v4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

/// The global IPv6 address the OS would send from to reach the internet
/// (often a temporary privacy address).
///
/// Connecting a UDP socket only picks a route; no packet is sent.
pub fn preferred_v6() -> Option<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0").ok()?;
    socket.connect("[2001:4860:4860::8888]:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V6(ip) if is_global_v6(&ip) => Some(ip),
        _ => None,
    }
}

/// Candidates derived from local interface addresses.
///
/// `Lan` only for private IPv4 (never CGNAT, which keeps VPN addresses such as
/// Tailscale's 100.x out), at most 2, in the order given.
///
/// `Ipv6` only when there is an IPv6 socket, `v6` being its local address. A
/// socket bound to one global address gives exactly that candidate: every
/// reply and probe leaves from it, and a peer's stateful firewall only lets
/// in what comes from the address it sent to. A socket bound to `[::]` gives
/// the global addresses of `addrs`, at most 3, in the order given.
pub fn local_candidates(addrs: &[IpAddr], v4_port: u16, v6: Option<SocketAddr>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = addrs
        .iter()
        .filter(|addr| matches!(addr, IpAddr::V4(ip) if classify_v4(*ip) == V4Class::Private))
        .take(MAX_LAN)
        .map(|addr| Candidate {
            kind: CandidateKind::Lan,
            addr: SocketAddr::new(*addr, v4_port),
        })
        .collect();
    let ipv6 = |addr: SocketAddr| Candidate {
        kind: CandidateKind::Ipv6,
        addr,
    };
    match v6 {
        Some(SocketAddr::V6(bound)) if bound.ip().is_unspecified() => out.extend(
            addrs
                .iter()
                .filter(|addr| matches!(addr, IpAddr::V6(ip) if is_global_v6(ip)))
                .take(MAX_IPV6)
                .map(|addr| ipv6(SocketAddr::new(*addr, bound.port()))),
        ),
        Some(SocketAddr::V6(bound)) if is_global_v6(bound.ip()) => {
            out.push(ipv6(SocketAddr::V6(bound)));
        }
        _ => {}
    }
    out
}

/// The router-mapped external address, if it is actually public.
pub fn mapped_candidate(ext: Option<SocketAddrV4>) -> Option<Candidate> {
    let ext = ext?;
    (classify_v4(*ext.ip()) == V4Class::Public).then_some(Candidate {
        kind: CandidateKind::Mapped,
        addr: SocketAddr::V4(ext),
    })
}

/// Are we behind carrier-grade NAT?
///
/// `primary` is the local IPv4 used for the default route, `router_ext` the
/// external IP the router reports, `stun_ip` the IP a STUN server sees.
/// `None` means there is not enough information to tell.
pub fn detect_cgnat(
    primary: Option<Ipv4Addr>,
    router_ext: Option<Ipv4Addr>,
    stun_ip: Option<Ipv4Addr>,
) -> Option<bool> {
    if primary.map(classify_v4) == Some(V4Class::Cgnat) {
        return Some(true);
    }
    if let Some(ext) = router_ext {
        // A shared, private or reserved address on the router's WAN side
        // means another NAT further up (DS-Lite's 192.0.0.0/29 is the ISP's).
        let behind = matches!(
            classify_v4(ext),
            V4Class::Cgnat | V4Class::Private | V4Class::Reserved
        ) || stun_ip.is_some_and(|s| s != ext);
        return Some(behind);
    }
    match (primary, stun_ip) {
        (Some(p), Some(s)) if classify_v4(p) == V4Class::Public && p == s => Some(false),
        _ => None,
    }
}

/// Guesses the kind of an address received without one (invite code).
pub fn infer_kind(addr: SocketAddr) -> CandidateKind {
    match addr {
        SocketAddr::V6(_) => CandidateKind::Ipv6,
        SocketAddr::V4(a) if classify_v4(*a.ip()) == V4Class::Private => CandidateKind::Lan,
        SocketAddr::V4(_) => CandidateKind::Mapped,
    }
}

/// Addresses that go into the invite code: the `Mapped`, the first `Ipv6` and
/// the first `Lan`, in that order (at most 3).
pub fn select_direct(cands: &[Candidate]) -> Vec<SocketAddr> {
    [CandidateKind::Mapped, CandidateKind::Ipv6, CandidateKind::Lan]
        .into_iter()
        .filter_map(|kind| cands.iter().find(|c| c.kind == kind).map(|c| c.addr))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(s: &str) -> Ipv4Addr { s.parse().unwrap() }

    #[test]
    fn classifies_ipv4() {
        assert_eq!(classify_v4(ip4("189.40.1.2")), V4Class::Public);
        assert_eq!(classify_v4(ip4("192.168.0.10")), V4Class::Private);
        assert_eq!(classify_v4(ip4("10.1.2.3")), V4Class::Private);
        assert_eq!(classify_v4(ip4("172.20.0.1")), V4Class::Private);
        assert_eq!(classify_v4(ip4("100.64.0.1")), V4Class::Cgnat);
        assert_eq!(classify_v4(ip4("100.127.255.254")), V4Class::Cgnat);
        assert_eq!(classify_v4(ip4("100.128.0.1")), V4Class::Public);
        assert_eq!(classify_v4(ip4("127.0.0.1")), V4Class::Loopback);
        assert_eq!(classify_v4(ip4("169.254.1.1")), V4Class::LinkLocal);
    }

    #[test]
    fn reserved_ranges_are_not_public() {
        let reserved = [
            "0.1.2.3", "192.0.0.2", "192.0.0.170", "198.18.0.1", "198.19.255.255", "224.0.0.1",
            "239.255.255.250", "240.0.0.1", "255.255.255.254", "255.255.255.255", "192.0.2.1",
            "198.51.100.7", "203.0.113.5",
        ];
        for ip in reserved {
            assert_eq!(classify_v4(ip4(ip)), V4Class::Reserved, "{ip}");
        }
        // Right next to them.
        let public = [
            "1.0.0.1", "192.0.1.1", "192.0.3.1", "198.17.255.255", "198.20.0.1",
            "198.51.101.1", "203.0.112.255", "203.0.114.1", "223.255.255.255",
        ];
        for ip in public {
            assert_eq!(classify_v4(ip4(ip)), V4Class::Public, "{ip}");
        }
        assert_eq!(classify_v4(ip4("0.0.0.0")), V4Class::Unspecified);
    }

    #[test]
    fn reserved_addresses_are_neither_mapped_nor_proof_of_a_public_ip() {
        // DS-Lite: the router's WAN side is 192.0.0.0/29 and the ISP does the NAT.
        assert_eq!(mapped_candidate(Some("192.0.0.2:4000".parse().unwrap())), None);
        assert_eq!(mapped_candidate(Some("203.0.113.5:4000".parse().unwrap())), None);
        assert_eq!(detect_cgnat(Some(ip4("192.168.0.10")), Some(ip4("192.0.0.2")), None), Some(true));
        // A reserved primary address that STUN echoes proves nothing.
        assert_eq!(detect_cgnat(Some(ip4("198.18.0.5")), None, Some(ip4("198.18.0.5"))), None);
    }

    #[test]
    fn only_global_ipv6() {
        assert!(is_global_v6(&"2804:14c::1".parse().unwrap()));
        assert!(!is_global_v6(&"fe80::1".parse().unwrap()));
        assert!(!is_global_v6(&"fd00::1".parse().unwrap()));
        assert!(!is_global_v6(&"::1".parse().unwrap()));
    }

    #[test]
    fn local_candidates_filter_and_cap() {
        let addrs: Vec<IpAddr> = ["192.168.0.10", "10.0.0.5", "172.16.0.9", "100.100.1.1",
            "2804::1", "2804::2", "2804::3", "2804::4", "fe80::1"]
            .iter().map(|s| s.parse().unwrap()).collect();
        let c = local_candidates(&addrs, 4000, Some("[::]:5000".parse().unwrap()));
        let lan: Vec<_> = c.iter().filter(|c| c.kind == CandidateKind::Lan).map(|c| c.addr).collect();
        assert_eq!(lan, vec!["192.168.0.10:4000".parse().unwrap(), "10.0.0.5:4000".parse().unwrap()]);
        assert_eq!(c.iter().filter(|c| c.kind == CandidateKind::Ipv6).count(), 3);
        assert!(c.iter().all(|c| c.addr.ip() != "100.100.1.1".parse::<IpAddr>().unwrap()));
        assert!(local_candidates(&addrs, 4000, None).iter().all(|c| c.kind == CandidateKind::Lan));
    }

    #[test]
    fn a_socket_bound_to_one_ipv6_address_advertises_only_that_one() {
        let addrs: Vec<IpAddr> = ["192.168.0.10", "2804::1", "2804::2", "fe80::1"]
            .iter().map(|s| s.parse().unwrap()).collect();
        let ipv6 = |v6: &str| -> Vec<SocketAddr> {
            local_candidates(&addrs, 4000, Some(v6.parse().unwrap()))
                .into_iter().filter(|c| c.kind == CandidateKind::Ipv6).map(|c| c.addr).collect()
        };
        // Bound to the preferred source address: that is where replies come
        // from, so it is the only one, listed on the interfaces or not.
        assert_eq!(ipv6("[2804::2]:5000"), vec!["[2804::2]:5000".parse().unwrap()]);
        assert_eq!(ipv6("[2804::9]:5000"), vec!["[2804::9]:5000".parse().unwrap()]);
        // Bound to [::]: the interface addresses, as before.
        assert_eq!(ipv6("[::]:5000"), vec!["[2804::1]:5000".parse().unwrap(), "[2804::2]:5000".parse().unwrap()]);
        // A non-global bound address advertises nothing.
        assert!(ipv6("[fe80::1]:5000").is_empty());
    }

    #[test]
    fn the_preferred_ipv6_address_is_global_when_there_is_one() {
        assert!(preferred_v6().is_none_or(|ip| is_global_v6(&ip)));
    }

    #[test]
    fn mapped_only_when_public() {
        assert_eq!(mapped_candidate(Some("189.40.1.2:4000".parse().unwrap())).map(|c| c.kind), Some(CandidateKind::Mapped));
        assert_eq!(mapped_candidate(Some("100.64.3.4:4000".parse().unwrap())), None);
        assert_eq!(mapped_candidate(Some("192.168.1.1:4000".parse().unwrap())), None);
        assert_eq!(mapped_candidate(None), None);
    }

    #[test]
    fn cgnat_detection() {
        assert_eq!(detect_cgnat(Some(ip4("100.70.1.2")), None, None), Some(true));
        assert_eq!(detect_cgnat(Some(ip4("192.168.0.10")), Some(ip4("100.64.9.9")), None), Some(true));
        assert_eq!(detect_cgnat(Some(ip4("192.168.0.10")), Some(ip4("189.40.1.2")), Some(ip4("200.1.1.1"))), Some(true));
        assert_eq!(detect_cgnat(Some(ip4("192.168.0.10")), Some(ip4("189.40.1.2")), Some(ip4("189.40.1.2"))), Some(false));
        assert_eq!(detect_cgnat(Some(ip4("189.40.1.2")), None, Some(ip4("189.40.1.2"))), Some(false));
        assert_eq!(detect_cgnat(Some(ip4("192.168.0.10")), None, Some(ip4("189.40.1.2"))), None);
    }

    #[test]
    fn direct_selection_and_kind_inference() {
        let c = |k, a: &str| Candidate { kind: k, addr: a.parse().unwrap() };
        use CandidateKind::*;
        let all = [c(Reflexive, "200.1.1.1:1"), c(Lan, "192.168.0.2:1"), c(Lan, "10.0.0.2:1"),
                   c(Ipv6, "[2804::1]:2"), c(Ipv6, "[2804::2]:2"), c(Mapped, "189.40.1.2:3")];
        let d = select_direct(&all);
        assert_eq!(d, vec!["189.40.1.2:3".parse().unwrap(), "[2804::1]:2".parse().unwrap(), "192.168.0.2:1".parse().unwrap()]);
        assert_eq!(d.iter().map(|a| infer_kind(*a)).collect::<Vec<_>>(), vec![Mapped, Ipv6, Lan]);
    }

    #[test]
    fn kind_display_and_priority() {
        use CandidateKind::*;
        let kinds = [Lan, Ipv6, Mapped, Reflexive, PeerReflexive];
        let names: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(names, vec!["lan", "ipv6", "mapped", "reflexive", "peer-reflexive"]);
        let prios: Vec<u8> = kinds.iter().map(|k| k.priority()).collect();
        assert_eq!(prios, vec![5, 4, 3, 2, 1]);
    }

    #[test]
    fn interface_addrs_exclude_loopback() {
        assert!(interface_addrs().iter().all(|a| !a.is_loopback()));
    }
}
