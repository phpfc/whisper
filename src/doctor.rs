//! `whisper doctor`: reports whether this network can host or join sessions.

use anyhow::Result;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::cancel::Cancel;
use crate::gather::{gather, NetSummary};
use crate::portmap::ProbeFlags;
use crate::signal::public_dht;
use crate::stun::NatMapping;

/// How long the DHT gets to bootstrap before it counts as unreachable.
const DHT_TIMEOUT: Duration = Duration::from_secs(10);

/// What `whisper doctor` found.
pub struct DoctorReport {
    pub ipv6: Option<Ipv6Addr>,
    pub probe: Option<ProbeFlags>,
    pub router_ext: Option<Ipv4Addr>,
    pub stun_ip: Option<Ipv4Addr>,
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

/// Time the public DHT takes to bootstrap, if it does within `DHT_TIMEOUT`.
async fn check_dht() -> Option<Duration> {
    let dht = public_dht().ok()?;
    let start = Instant::now();
    let bootstrapped = tokio::time::timeout(DHT_TIMEOUT, dht.bootstrapped())
        .await
        .ok()?;
    bootstrapped.then(|| start.elapsed())
}

/// Gathers network info, checks the DHT and prints the report. Ctrl-C ends it
/// with a `Cancelled` error, after releasing any router mapping.
pub async fn run(cancel: &Cancel) -> Result<()> {
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
        stun_ip: g.stun_ip(),
        summary: g.summary,
        dht: cancel.run(check_dht()).await?,
    };
    print!("{}", render(&report));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            stun_ip: Some("189.40.12.34".parse().unwrap()),
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
            stun_ip: None,
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
    }
}
