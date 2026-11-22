//! `whisper doctor`: reports whether this network can host or join sessions.

use anyhow::Result;
use mainline::async_dht::AsyncDht;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::cancel::Cancel;
use crate::connect::ConnectError;
use crate::gather::{gather, NetSummary};
use crate::portmap::ProbeFlags;
use crate::signal::{bootstrap_time, public_dht};
use crate::stun::NatMapping;

/// How long the DHT gets to bootstrap before it counts as unreachable.
const DHT_TIMEOUT: Duration = Duration::from_secs(10);

/// What `whisper doctor` found.
pub struct DoctorReport {
    pub ipv6: Option<Ipv6Addr>,
    pub probe: Option<ProbeFlags>,
    pub router_ext: Option<Ipv4Addr>,
    /// Some STUN server told us our address.
    pub stun_answered: bool,
    pub summary: NetSummary,
    /// Time the DHT took to bootstrap; `None` if it did not.
    pub dht: Option<Duration>,
}

/// `189.40.12.34` -> `189.40.x.x`
pub fn mask_v4(ip: Ipv4Addr) -> String {
    let [a, b, _, _] = ip.octets();
    format!("{a}.{b}.x.x")
}

/// `2804:14c:65a1::1` -> `2804:14c:…`
pub fn mask_v6(ip: Ipv6Addr) -> String {
    let s = ip.segments();
    format!("{:x}:{:x}:…", s[0], s[1])
}

/// One-line conclusion for the network.
pub fn verdict(s: &NetSummary) -> &'static str {
    if s.mapped {
        "can host sessions"
    } else if s.ipv6 {
        "can likely reach peers that have IPv6"
    } else if s.nat == NatMapping::EndpointIndependent {
        "cannot host; hole punching likely works"
    } else {
        "direct connections unlikely from this network"
    }
}

/// What kind of network this is, as shown to the user when no direct path
/// exists. Hosting comes first: a mapped port or IPv6 works even behind a
/// symmetric NAT or CGNAT.
pub fn describe(s: &NetSummary) -> &'static str {
    let symmetric = s.nat == NatMapping::EndpointDependent;
    let cgnat = s.cgnat == Some(true);
    if s.can_host() {
        "can host"
    } else if symmetric && cgnat {
        "symmetric NAT behind CGNAT"
    } else if symmetric {
        "symmetric NAT"
    } else if cgnat {
        "behind CGNAT, cannot host"
    } else {
        "cannot host (no IPv6, no port mapping)"
    }
}

/// Whether the DHT, the only way to find a peer the code has no address for,
/// could be reached from this network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Our DHT node bootstrapped, or it is not known yet.
    Fine,
    /// No DHT node answered, though a STUN server did: something filters the
    /// DHT.
    NoDht,
    /// No DHT node and no STUN server answered: UDP looks blocked.
    NoUdp,
}

/// `dht_bootstrapped` is `None` while the bootstrap check is still running;
/// `stun_answered` says whether any STUN server gave us our address.
pub fn reach(dht_bootstrapped: Option<bool>, stun_answered: bool) -> Reach {
    match (dht_bootstrapped, stun_answered) {
        (Some(false), true) => Reach::NoDht,
        (Some(false), false) => Reach::NoUdp,
        _ => Reach::Fine,
    }
}

/// What is wrong with the DHT, as the start of a sentence; `None` if nothing.
fn reach_note(reach: Reach) -> Option<&'static str> {
    match reach {
        Reach::Fine => None,
        Reach::NoDht => Some("The DHT is unreachable from this network"),
        Reach::NoUdp => {
            Some("This network seems to block UDP (no STUN server or DHT node answered)")
        }
    }
}

/// Why nobody joined the creator's session, for the user.
pub fn explain_no_one_joined(reach: Reach) -> String {
    match reach_note(reach) {
        None => ConnectError::NoOneJoined.to_string(),
        Some(note) => format!(
            "No one joined within 10 minutes. {note}, so your peer may not have been able to find you. Try another network or run `whisper doctor`."
        ),
    }
}

/// Why the connection failed, for the user. `remote` is `None` when the other
/// peer's candidates never arrived, and `reach` then says whether the DHT
/// that should have brought them was reachable.
pub fn explain_no_path(own: &NetSummary, remote: Option<&NetSummary>, reach: Reach) -> String {
    match (remote, reach_note(reach)) {
        (None, Some(note)) => format!(
            "The other peer could not be reached. {note}, so only the addresses in the code could be tried. Try another network or run `whisper doctor`."
        ),
        (None, None) => "The other peer never showed up. Check that the code is complete and that they are still waiting, or run `whisper doctor`.".to_string(),
        (Some(remote), _) => format!(
            "No direct path. You: {}. Other peer: {}. Try another network (Wi-Fi instead of mobile data) or run `whisper doctor`.",
            describe(own),
            describe(remote)
        ),
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// The report as shown to the user. Addresses are masked.
pub fn render(r: &DoctorReport) -> String {
    let ipv6 = match r.ipv6 {
        Some(ip) => format!("yes ({})", mask_v6(ip)),
        None => "no".to_string(),
    };

    let ext = r.router_ext.map(mask_v4);
    let router = match (r.probe.filter(|p| p.upnp || p.nat_pmp || p.pcp), ext) {
        (Some(p), ext) => {
            let mut line = format!(
                "UPnP {}   NAT-PMP {}   PCP {}",
                yes_no(p.upnp),
                yes_no(p.nat_pmp),
                yes_no(p.pcp)
            );
            if let Some(ext) = ext {
                line.push_str(&format!("   external IP {ext}"));
            }
            line
        }
        // The probe got no answer but a mapping exists anyway.
        (None, Some(ext)) => format!("external IP {ext}"),
        (None, None) => "no port mapping protocol found".to_string(),
    };

    let cgnat = match r.summary.cgnat {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    };

    let nat = match r.summary.nat {
        NatMapping::EndpointIndependent => "endpoint-independent (good for hole punching)",
        NatMapping::EndpointDependent => "symmetric (hole punching unlikely)",
        NatMapping::Unknown if r.stun_answered => "unknown (only one STUN server answered)",
        NatMapping::Unknown => "unknown (STUN unreachable)",
    };

    let dht = match r.dht {
        Some(t) => format!("reachable ({:.1} s)", t.as_secs_f64()),
        None => "unreachable".to_string(),
    };

    format!(
        "\
Global IPv6:   {ipv6}
Router:        {router}
CGNAT:         {cgnat}
NAT mapping:   {nat}
DHT:           {dht}
Verdict:       {}
",
        verdict(&r.summary)
    )
}

/// Printed before gathering: the check maps a router port, and the user is
/// told before anything is done to the router.
const ROUTER_NOTICE: &str = "Checking your router (a test port is opened and closed again)...";

/// Time the public DHT takes to bootstrap, if it does within `DHT_TIMEOUT`.
async fn check_dht() -> Option<Duration> {
    check_dht_with(public_dht).await
}

/// [`check_dht`] with the node started by `start`. That runs off the async
/// workers (it resolves the bootstrap hostnames with blocking lookups), so
/// Ctrl-C still gets through while it does.
async fn check_dht_with(
    start: impl FnOnce() -> std::io::Result<AsyncDht> + Send + 'static,
) -> Option<Duration> {
    let dht = tokio::task::spawn_blocking(start).await.ok()?.ok()?;
    bootstrap_time(&dht, DHT_TIMEOUT).await
}

/// Gathers network info, checks the DHT and prints the report. Ctrl-C ends it
/// with a `Cancelled` error, after releasing any router mapping.
pub async fn run(cancel: &Cancel) -> Result<()> {
    println!("{ROUTER_NOTICE}");
    let mut g = gather(cancel).await?;

    // The mapping is only needed to learn whether the router grants one, so
    // release it now rather than keeping it open during the DHT check.
    if let Some(pm) = g.portmap.take() {
        pm.close().await;
    }

    let report = DoctorReport {
        ipv6: g.ipv6_addr,
        probe: g.probe,
        router_ext: g.router_ext.map(|a| *a.ip()),
        stun_answered: g.stun_addr.is_some(),
        summary: g.summary,
        dht: cancel.run(check_dht()).await?,
    };
    print!("{}", render(&report));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn masks_addresses() {
        assert_eq!(mask_v4("189.40.12.34".parse().unwrap()), "189.40.x.x");
        assert_eq!(mask_v6("2804:14c:65a1::1".parse().unwrap()), "2804:14c:…");
    }

    #[test]
    fn verdicts() {
        let s = |ipv6, mapped, nat| NetSummary {
            ipv6,
            mapped,
            cgnat: None,
            nat,
        };
        use NatMapping::*;
        assert_eq!(verdict(&s(false, true, Unknown)), "can host sessions");
        assert_eq!(
            verdict(&s(true, false, Unknown)),
            "can likely reach peers that have IPv6"
        );
        assert_eq!(
            verdict(&s(false, false, EndpointIndependent)),
            "cannot host; hole punching likely works"
        );
        assert_eq!(
            verdict(&s(false, false, EndpointDependent)),
            "direct connections unlikely from this network"
        );
    }

    #[test]
    fn renders_report() {
        let r = DoctorReport {
            ipv6: Some("2804:14c:65a1::1".parse().unwrap()),
            probe: Some(ProbeFlags {
                upnp: true,
                nat_pmp: false,
                pcp: false,
            }),
            router_ext: Some("189.40.12.34".parse().unwrap()),
            stun_answered: true,
            summary: NetSummary {
                ipv6: true,
                mapped: true,
                cgnat: Some(false),
                nat: NatMapping::EndpointIndependent,
            },
            dht: Some(Duration::from_millis(2100)),
        };
        assert_eq!(
            render(&r),
            "\
Global IPv6:   yes (2804:14c:…)
Router:        UPnP yes   NAT-PMP no   PCP no   external IP 189.40.x.x
CGNAT:         no
NAT mapping:   endpoint-independent (good for hole punching)
DHT:           reachable (2.1 s)
Verdict:       can host sessions
"
        );
    }

    #[test]
    fn renders_report_variants() {
        let r = DoctorReport {
            ipv6: None,
            probe: Some(ProbeFlags {
                upnp: false,
                nat_pmp: false,
                pcp: false,
            }),
            router_ext: None,
            stun_answered: false,
            summary: NetSummary {
                ipv6: false,
                mapped: false,
                cgnat: Some(true),
                nat: NatMapping::EndpointDependent,
            },
            dht: None,
        };
        assert_eq!(
            render(&r),
            "\
Global IPv6:   no
Router:        no port mapping protocol found
CGNAT:         yes
NAT mapping:   symmetric (hole punching unlikely)
DHT:           unreachable
Verdict:       direct connections unlikely from this network
"
        );

        let r = DoctorReport {
            probe: None,
            summary: NetSummary {
                cgnat: None,
                nat: NatMapping::Unknown,
                ..r.summary
            },
            ..r
        };
        let out = render(&r);
        assert!(out.contains("\nCGNAT:         unknown\n"));
        assert!(out.contains("\nNAT mapping:   unknown (STUN unreachable)\n"));

        // One server answered: we have an address, just not the NAT type.
        // Nothing else changes.
        let one = render(&DoctorReport {
            stun_answered: true,
            ..r
        });
        assert_eq!(
            one,
            out.replace(
                "unknown (STUN unreachable)",
                "unknown (only one STUN server answered)"
            )
        );
    }

    #[test]
    fn says_that_it_tests_the_router() {
        assert_eq!(
            ROUTER_NOTICE,
            "Checking your router (a test port is opened and closed again)..."
        );
    }

    /// A DHT node start that blocks for `for_ms` and then fails.
    fn slow_start(for_ms: u64) -> impl FnOnce() -> std::io::Result<AsyncDht> + Send + 'static {
        move || {
            std::thread::sleep(Duration::from_millis(for_ms));
            Err(std::io::Error::other("no DHT here"))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_dht_node_starts_off_the_async_workers() {
        let ticks = std::sync::atomic::AtomicU32::new(0);
        let ticker = async {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                ticks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        };
        // One worker thread only: if the start blocked it, nothing would tick.
        tokio::select! {
            r = check_dht_with(slow_start(300)) => assert_eq!(r, None),
            () = ticker => unreachable!(),
        }
        let ticks = ticks.load(std::sync::atomic::Ordering::Relaxed);
        assert!(ticks >= 10, "{ticks} ticks");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ctrl_c_ends_the_dht_check_while_the_node_starts() {
        let (tx, cancel) = Cancel::channel();
        let press = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            tx.send(true).unwrap();
        };
        let started = Instant::now();
        let (result, ()) = tokio::join!(cancel.run(check_dht_with(slow_start(1000))), press);
        assert!(result.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
    }

    fn s(ipv6: bool, mapped: bool, cgnat: Option<bool>, nat: NatMapping) -> NetSummary {
        NetSummary {
            ipv6,
            mapped,
            cgnat,
            nat,
        }
    }

    #[test]
    fn describes_networks() {
        use NatMapping::*;
        assert_eq!(
            describe(&s(false, false, Some(true), EndpointDependent)),
            "symmetric NAT behind CGNAT"
        );
        assert_eq!(
            describe(&s(false, false, None, EndpointDependent)),
            "symmetric NAT"
        );
        assert_eq!(
            describe(&s(false, false, Some(true), EndpointIndependent)),
            "behind CGNAT, cannot host"
        );
        assert_eq!(
            describe(&s(false, false, None, Unknown)),
            "cannot host (no IPv6, no port mapping)"
        );
        assert_eq!(describe(&s(false, true, None, Unknown)), "can host");
    }

    #[test]
    fn hosting_wins_over_nat_and_cgnat() {
        use NatMapping::*;
        // A mapped port or IPv6 works even behind a symmetric NAT or CGNAT.
        assert_eq!(
            describe(&s(false, true, Some(true), EndpointDependent)),
            "can host"
        );
        assert_eq!(
            describe(&s(true, false, Some(true), EndpointDependent)),
            "can host"
        );
    }

    #[test]
    fn explains_missing_and_blocked_peers() {
        use NatMapping::*;
        let own = s(false, false, Some(true), EndpointDependent);
        assert_eq!(
            explain_no_path(&own, None, Reach::Fine),
            "The other peer never showed up. Check that the code is complete and that they are still waiting, or run `whisper doctor`."
        );
        let other = s(false, false, None, Unknown);
        let no_path = "No direct path. You: symmetric NAT behind CGNAT. Other peer: cannot host (no IPv6, no port mapping). Try another network (Wi-Fi instead of mobile data) or run `whisper doctor`.";
        // The peer's record arrived, so the DHT worked whatever the check said.
        for reach in [Reach::Fine, Reach::NoDht, Reach::NoUdp] {
            assert_eq!(explain_no_path(&own, Some(&other), reach), no_path);
        }
    }

    #[test]
    fn a_dht_out_of_reach_is_told_apart_from_blocked_udp() {
        assert_eq!(reach(Some(true), true), Reach::Fine);
        assert_eq!(reach(Some(true), false), Reach::Fine);
        // Not known yet: no claim either way.
        assert_eq!(reach(None, false), Reach::Fine);
        assert_eq!(reach(Some(false), true), Reach::NoDht);
        assert_eq!(reach(Some(false), false), Reach::NoUdp);
    }

    #[test]
    fn explains_an_unreachable_dht() {
        let own = s(false, false, None, NatMapping::EndpointIndependent);
        assert_eq!(
            explain_no_path(&own, None, Reach::NoDht),
            "The other peer could not be reached. The DHT is unreachable from this network, so only the addresses in the code could be tried. Try another network or run `whisper doctor`."
        );
        assert_eq!(
            explain_no_path(&own, None, Reach::NoUdp),
            "The other peer could not be reached. This network seems to block UDP (no STUN server or DHT node answered), so only the addresses in the code could be tried. Try another network or run `whisper doctor`."
        );
        assert_eq!(
            explain_no_one_joined(Reach::Fine),
            "No one joined within 10 minutes. Create a new session to try again."
        );
        assert_eq!(
            explain_no_one_joined(Reach::NoDht),
            "No one joined within 10 minutes. The DHT is unreachable from this network, so your peer may not have been able to find you. Try another network or run `whisper doctor`."
        );
        assert_eq!(
            explain_no_one_joined(Reach::NoUdp),
            "No one joined within 10 minutes. This network seems to block UDP (no STUN server or DHT node answered), so your peer may not have been able to find you. Try another network or run `whisper doctor`."
        );
    }
}
