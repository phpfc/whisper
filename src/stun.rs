use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use crate::util::{is_transient, list_from_env};

/// Environment variable that replaces [`STUN_SERVERS`]: a comma-separated list
/// of `host:port`. Meant for tests and the NAT lab, where nothing reaches the
/// public servers.
pub const STUN_SERVERS_ENV: &str = "WHISPER_STUN_SERVERS";

/// Public STUN servers - free, reliable, always available.
///
/// The first two come from different operators: `probe_nat` asks them to tell
/// whether the NAT keeps the same external mapping regardless of destination.
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
];

/// How long `probe_nat` waits for each server.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// How long `probe_nat` takes at most, name lookups included. On a network
/// that drops UDP no server answers, and asking each in turn for
/// `PROBE_TIMEOUT` would hold everything up for about 20 s.
const PROBE_TOTAL: Duration = Duration::from_secs(6);

/// How the NAT maps our local port when talking to different destinations.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatMapping {
    /// Same external ip:port for every destination (hole punching works).
    EndpointIndependent,
    /// A new external ip:port per destination (symmetric NAT).
    EndpointDependent,
    /// Not enough STUN answers to tell.
    Unknown,
}

/// Builds a STUN Binding Request (no attributes) for the given transaction id.
/// https://datatracker.ietf.org/doc/html/rfc5389
pub fn build_binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut request = [0u8; 20];
    // Message Type: Binding Request (0x0001)
    request[0..2].copy_from_slice(&[0x00, 0x01]);
    // Message Length: 0 (no attributes)
    request[2..4].copy_from_slice(&[0x00, 0x00]);
    // Magic Cookie (fixed value)
    request[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    // Transaction ID (96 bits)
    request[8..20].copy_from_slice(txid);
    request
}

/// Builds a Binding Response (0x0101) for the given transaction id, carrying
/// one XOR-MAPPED-ADDRESS attribute (0x0020) for `addr`: the address the
/// server saw the request come from.
// The app only parses responses; this is for the tests and the
// `stun_responder` example, which includes this file.
#[allow(dead_code)]
pub fn build_binding_response(txid: &[u8; 12], addr: SocketAddrV4) -> Vec<u8> {
    const COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
    let mut response = Vec::with_capacity(32);
    // Message Type: Binding Response (0x0101)
    response.extend_from_slice(&[0x01, 0x01]);
    // Message Length: one attribute = 4-byte header + 8-byte value
    response.extend_from_slice(&[0x00, 12]);
    response.extend_from_slice(&COOKIE);
    response.extend_from_slice(txid);
    // XOR-MAPPED-ADDRESS: reserved byte, family (IPv4), then the port XORed
    // with the top half of the cookie and the address XORed with all of it.
    response.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
    for (octet, key) in addr.ip().octets().iter().zip(COOKIE) {
        response.push(octet ^ key);
    }
    response
}

/// Parses a STUN Binding Response and returns the IPv4 address the server saw
/// us at. Fails if the datagram is not a Binding Response for `txid`.
pub fn parse_binding_response(buf: &[u8], txid: &[u8; 12]) -> Result<SocketAddr> {
    let len = buf.len();
    if len < 20 {
        return Err(anyhow!("STUN response too short"));
    }

    // Verify it's a Binding Response (0x0101)
    if buf[0] != 0x01 || buf[1] != 0x01 {
        return Err(anyhow!("Not a STUN Binding Response"));
    }

    // Verify transaction ID matches
    if buf[8..20] != txid[..] {
        return Err(anyhow!("Transaction ID mismatch"));
    }

    // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut offset = 20;

    while offset + 4 <= 20 + msg_len && offset + 4 <= len {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > len {
            break;
        }

        match attr_type {
            0x0020 => {
                // XOR-MAPPED-ADDRESS
                if attr_len >= 8 {
                    let family = buf[offset + 1];
                    if family == 0x01 {
                        // IPv4
                        let port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) ^ 0x2112;
                        let ip = [
                            buf[offset + 4] ^ 0x21,
                            buf[offset + 5] ^ 0x12,
                            buf[offset + 6] ^ 0xA4,
                            buf[offset + 7] ^ 0x42,
                        ];
                        let addr = SocketAddr::from((ip, port));
                        return Ok(addr);
                    }
                }
            }
            0x0001 => {
                // MAPPED-ADDRESS (fallback)
                if attr_len >= 8 {
                    let family = buf[offset + 1];
                    if family == 0x01 {
                        // IPv4
                        let port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                        let ip = [buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]];
                        let addr = SocketAddr::from((ip, port));
                        return Ok(addr);
                    }
                }
            }
            _ => {}
        }

        // Move to next attribute (aligned to 4 bytes)
        offset += (attr_len + 3) & !3;
    }

    Err(anyhow!("No address found in STUN response"))
}

/// Compares the external address two different STUN servers saw for the same
/// local socket: identical means the NAT reuses the mapping per local port.
pub fn classify_mapping(a: SocketAddr, b: SocketAddr) -> NatMapping {
    if a == b {
        NatMapping::EndpointIndependent
    } else {
        NatMapping::EndpointDependent
    }
}

/// Asks `server` which address it sees us at, using `socket` (so the result is
/// the NAT mapping of that socket's local port). Datagrams that are not a
/// matching Binding Response are ignored until `timeout` expires.
pub async fn query(
    socket: &tokio::net::UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr> {
    let txid: [u8; 12] = rand::random();
    socket.send_to(&build_binding_request(&txid), server).await?;

    let wait = wait_for_response(&txid, async |buf| {
        socket.recv_from(buf).await.map(|(len, _)| len)
    });

    tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_| anyhow!("STUN query to {} timed out", server))?
}

/// Reads datagrams with `recv` until one is the Binding Response for `txid`.
/// Datagrams that are not are ignored, and so are the receive errors that
/// belong to some other datagram (see [`is_transient`]): `probe_nat` reuses one
/// socket for several queries, and on Windows the ICMP port-unreachable for an
/// earlier send would otherwise fail the next receive of a healthy query.
async fn wait_for_response(
    txid: &[u8; 12],
    mut recv: impl AsyncFnMut(&mut [u8]) -> std::io::Result<usize>,
) -> Result<SocketAddr> {
    let mut buf = [0u8; 512];
    loop {
        match recv(&mut buf).await {
            Ok(len) => {
                if let Ok(addr) = parse_binding_response(&buf[..len], txid) {
                    return Ok(addr);
                }
            }
            Err(e) if is_transient(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Resolves a "host:port" STUN server to its first IPv4 address.
async fn resolve_ipv4(server: &str) -> Option<SocketAddr> {
    tokio::net::lookup_host(server)
        .await
        .ok()?
        .find(|addr| addr.is_ipv4())
}

/// Queries one STUN server by name; `None` if it does not resolve or answer.
async fn query_by_name(
    socket: &tokio::net::UdpSocket,
    server: &str,
    timeout: Duration,
) -> Option<SocketAddr> {
    let server_addr = resolve_ipv4(server).await?;
    query(socket, server_addr, timeout).await.ok()
}

/// The STUN servers to use: the ones in `WHISPER_STUN_SERVERS` if it names any,
/// else [`STUN_SERVERS`].
pub fn stun_servers() -> Vec<String> {
    list_from_env(STUN_SERVERS_ENV)
        .unwrap_or_else(|| STUN_SERVERS.iter().map(|s| s.to_string()).collect())
}

/// Discovers our public address through `socket` and whether the NAT keeps the
/// same mapping across destinations, asking the servers from [`stun_servers`].
pub async fn probe_nat(socket: &tokio::net::UdpSocket) -> (Option<SocketAddr>, NatMapping) {
    probe_nat_with(socket, &stun_servers(), PROBE_TIMEOUT, PROBE_TOTAL).await
}

/// [`probe_nat`] against an explicit list, waiting `timeout` for each server
/// and `total` for everything. The first two servers are asked, in sequence:
///
/// - Both answered: `(Some(first), classify_mapping(first, second))`.
/// - Only one answered: `(Some(it), Unknown)`.
/// - Neither answered: the rest of the list is tried just to learn our address
///   (`(Some(addr), Unknown)`), else `(None, Unknown)`.
///
/// A server still being asked when `total` runs out counts as silent; the
/// answers already in are kept.
pub async fn probe_nat_with<S: AsRef<str>>(
    socket: &tokio::net::UdpSocket,
    servers: &[S],
    timeout: Duration,
    total: Duration,
) -> (Option<SocketAddr>, NatMapping) {
    let deadline = tokio::time::Instant::now() + total;
    let ask = async |server: Option<&S>| {
        let server = server?;
        let query = query_by_name(socket, server.as_ref(), timeout);
        tokio::time::timeout_at(deadline, query).await.ok()?
    };
    let first = ask(servers.first()).await;
    let second = ask(servers.get(1)).await;

    match (first, second) {
        (Some(a), Some(b)) => (Some(a), classify_mapping(a, b)),
        (Some(addr), None) | (None, Some(addr)) => (Some(addr), NatMapping::Unknown),
        (None, None) => {
            for server in servers.iter().skip(2) {
                if let Some(addr) = ask(Some(server)).await {
                    return (Some(addr), NatMapping::Unknown);
                }
            }
            (None, NatMapping::Unknown)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_header_cookie_and_txid() {
        let r = build_binding_request(&[1; 12]);
        assert_eq!(&r[0..4], &[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(&r[4..8], &[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(&r[8..20], &[1; 12]);
    }

    #[test]
    fn response_is_a_binding_response_with_xor_mapped_address() {
        let r = build_binding_response(&[9; 12], "203.0.113.5:54321".parse().unwrap());
        assert_eq!(
            r,
            [
                &[0x01, 0x01, 0x00, 12][..], // Binding Response, 12 bytes of attributes
                &[0x21, 0x12, 0xA4, 0x42],   // magic cookie
                &[9; 12],                    // transaction id
                &[0x00, 0x20, 0x00, 0x08],   // XOR-MAPPED-ADDRESS, 8 bytes
                &[0x00, 0x01, 0xF5, 0x23],   // IPv4, port 54321 ^ 0x2112
                &[0xEA, 0x12, 0xD5, 0x47],   // 203.0.113.5 ^ cookie
            ]
            .concat()
        );
    }

    #[test]
    fn default_probe_pair_comes_from_two_operators() {
        assert_eq!(
            STUN_SERVERS[..2],
            ["stun.l.google.com:19302", "stun.cloudflare.com:3478"]
        );
    }

    #[test]
    fn parses_xor_mapped_address() {
        let txid = [7; 12];
        let addr: SocketAddrV4 = "203.0.113.5:54321".parse().unwrap();
        assert_eq!(
            parse_binding_response(&build_binding_response(&txid, addr), &txid).unwrap(),
            SocketAddr::V4(addr)
        );
    }

    #[test]
    fn rejects_wrong_txid_and_short_buffers() {
        let resp = build_binding_response(&[7; 12], "203.0.113.5:1".parse().unwrap());
        assert!(parse_binding_response(&resp, &[8; 12]).is_err());
        assert!(parse_binding_response(&[0u8; 10], &[0; 12]).is_err());
    }

    #[test]
    fn same_mapping_is_endpoint_independent() {
        let a: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        let b: SocketAddr = "203.0.113.5:4001".parse().unwrap();
        assert_eq!(classify_mapping(a, a), NatMapping::EndpointIndependent);
        assert_eq!(classify_mapping(a, b), NatMapping::EndpointDependent);
    }

    #[tokio::test]
    async fn query_skips_unrelated_datagrams_until_matching_response() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let mapped: SocketAddrV4 = "203.0.113.5:54321".parse().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(len, 20);
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            // Garbage and a response for another transaction come first.
            server.send_to(b"not stun", from).await.unwrap();
            let other = build_binding_response(&[0xEE; 12], "198.51.100.9:1".parse().unwrap());
            server.send_to(&other, from).await.unwrap();
            server.send_to(&build_binding_response(&txid, mapped), from).await.unwrap();
        });

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = query(&client, server_addr, Duration::from_secs(2)).await.unwrap();
        assert_eq!(addr, SocketAddr::V4(mapped));
    }

    /// Feeds `wait_for_response` the scripted receive results, one per call.
    async fn wait_over(
        txid: &[u8; 12],
        script: Vec<std::io::Result<Vec<u8>>>,
    ) -> Result<SocketAddr> {
        let mut script = std::collections::VecDeque::from(script);
        wait_for_response(txid, async |buf: &mut [u8]| {
            let datagram = script.pop_front().expect("script ran out")?;
            buf[..datagram.len()].copy_from_slice(&datagram);
            Ok(datagram.len())
        })
        .await
    }

    #[tokio::test]
    async fn stale_receive_errors_do_not_abort_a_query() {
        use std::io::{Error, ErrorKind};
        // What Windows does when an earlier send drew an ICMP port-unreachable.
        let txid = [3; 12];
        let mapped: SocketAddrV4 = "203.0.113.5:54321".parse().unwrap();
        let addr = wait_over(
            &txid,
            vec![
                Err(Error::from(ErrorKind::ConnectionReset)),
                Ok(b"not stun".to_vec()),
                Err(Error::from(ErrorKind::ConnectionReset)),
                Ok(build_binding_response(&txid, mapped)),
            ],
        )
        .await
        .unwrap();
        assert_eq!(addr, SocketAddr::V4(mapped));
    }

    #[tokio::test]
    async fn a_failing_socket_still_ends_the_query() {
        use std::io::{Error, ErrorKind};
        let result = wait_over(&[3; 12], vec![Err(Error::from(ErrorKind::PermissionDenied))]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn query_times_out_when_nobody_answers() {
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = query(&client, silent.local_addr().unwrap(), Duration::from_millis(100)).await;
        assert!(result.is_err());
    }

    const SHORT: Duration = Duration::from_millis(150);
    /// An overall limit that never kicks in.
    const LONG: Duration = Duration::from_secs(30);

    /// A server that receives and never answers; keep the socket alive so the
    /// sender gets no ICMP error either.
    async fn silent_server() -> (tokio::net::UdpSocket, String) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        (socket, addr)
    }

    async fn loopback_client() -> tokio::net::UdpSocket {
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    #[tokio::test]
    async fn two_servers_with_one_mapping_are_endpoint_independent() {
        let r = spawn_responder().await.to_string();
        let client = loopback_client().await;
        let (addr, mapping) = probe_nat_with(&client, &[&r, &r], SHORT, LONG).await;
        assert_eq!(addr, Some(client.local_addr().unwrap()));
        assert_eq!(mapping, NatMapping::EndpointIndependent);
    }

    #[tokio::test]
    async fn one_answering_probe_server_leaves_the_mapping_unknown() {
        let r = spawn_responder().await.to_string();
        let (_keep, silent) = silent_server().await;
        let client = loopback_client().await;
        let local = Some(client.local_addr().unwrap());

        let answered_second = probe_nat_with(&client, &[&silent, &r], SHORT, LONG).await;
        assert_eq!(answered_second, (local, NatMapping::Unknown));
        let answered_first = probe_nat_with(&client, &[&r, &silent], SHORT, LONG).await;
        assert_eq!(answered_first, (local, NatMapping::Unknown));
        let only_one = probe_nat_with(&client, &[&r], SHORT, LONG).await;
        assert_eq!(only_one, (local, NatMapping::Unknown));
    }

    #[tokio::test]
    async fn the_rest_of_the_list_is_tried_when_both_probe_servers_are_silent() {
        let r = spawn_responder().await.to_string();
        let (_keep, silent) = silent_server().await;
        let client = loopback_client().await;

        let result = probe_nat_with(&client, &[&silent, &silent, &r], SHORT, LONG).await;
        assert_eq!(
            result,
            (Some(client.local_addr().unwrap()), NatMapping::Unknown)
        );
        let nobody = probe_nat_with(&client, &[&silent, &silent], SHORT, LONG).await;
        assert_eq!(nobody, (None, NatMapping::Unknown));
        let empty: [&str; 0] = [];
        assert_eq!(
            probe_nat_with(&client, &empty, SHORT, LONG).await,
            (None, NatMapping::Unknown)
        );
    }

    #[tokio::test]
    async fn the_whole_probe_stops_at_its_overall_limit() {
        let (_k1, s1) = silent_server().await;
        let (_k2, s2) = silent_server().await;
        let (_k3, s3) = silent_server().await;
        let client = loopback_client().await;
        let started = std::time::Instant::now();
        // 3 x 400 ms one server after the other, but only 300 ms in all.
        let result = probe_nat_with(
            &client,
            &[&s1, &s2, &s3],
            Duration::from_millis(400),
            Duration::from_millis(300),
        )
        .await;
        let elapsed = started.elapsed();
        assert_eq!(result, (None, NatMapping::Unknown));
        assert!(elapsed < Duration::from_millis(600), "{elapsed:?}");
    }

    #[tokio::test]
    async fn an_answer_before_the_overall_limit_is_kept() {
        let r = spawn_responder().await.to_string();
        let (_keep, silent) = silent_server().await;
        let client = loopback_client().await;
        let started = std::time::Instant::now();
        // The silent second server only gets what is left of the 200 ms.
        let result = probe_nat_with(
            &client,
            &[&r, &silent],
            Duration::from_millis(1000),
            Duration::from_millis(200),
        )
        .await;
        let elapsed = started.elapsed();
        assert_eq!(
            result,
            (Some(client.local_addr().unwrap()), NatMapping::Unknown)
        );
        assert!(elapsed < Duration::from_millis(600), "{elapsed:?}");
    }

    #[test]
    fn probing_takes_about_six_seconds_at_most() {
        assert_eq!(PROBE_TOTAL, Duration::from_secs(6));
    }

    /// Starts a STUN responder on a loopback port that answers every request
    /// with the sender's own address, as a server on the public side would.
    async fn spawn_responder() -> SocketAddr {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (len, from) = server.recv_from(&mut buf).await.unwrap();
                assert_eq!(len, 20);
                let txid: [u8; 12] = buf[8..20].try_into().unwrap();
                let SocketAddr::V4(from4) = from else { continue };
                server.send_to(&build_binding_response(&txid, from4), from).await.unwrap();
            }
        });
        addr
    }

    /// Sets an environment variable for the length of one test.
    struct EnvVar(&'static str);

    impl EnvVar {
        fn set(name: &'static str, value: &str) -> Self {
            std::env::set_var(name, value);
            EnvVar(name)
        }
    }

    impl Drop for EnvVar {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    // The only test that sets WHISPER_STUN_SERVERS (the process environment is
    // shared by tests running in parallel): everything else goes through
    // `probe_nat_with`. Only the ignored network test also reads it.
    #[tokio::test]
    async fn env_override_points_probe_at_local_responder() {
        let responder = spawn_responder().await;
        let _env = EnvVar::set(STUN_SERVERS_ENV, &format!("{responder}, {responder}"));

        let client = loopback_client().await;
        let (addr, mapping) = probe_nat(&client).await;

        assert_eq!(addr, Some(client.local_addr().unwrap()));
        assert_eq!(mapping, NatMapping::EndpointIndependent);
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn probe_nat_against_public_servers() {
        let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let (addr, _) = probe_nat(&s).await;
        assert!(addr.is_some());
    }
}
