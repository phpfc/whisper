# whisper P2P sem custo de infra: plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dois peers se conectam diretamente com um único código, sem configuração manual de rede e sem nenhum servidor do projeto, usando IPv6, abertura de porta no roteador, hole punching e sinalização pela DHT do BitTorrent.

**Architecture:** Cada peer coleta candidatos (LAN, IPv6, porta mapeada no roteador, endereço visto pelo STUN). Os candidatos diretos de quem cria vão no código v3; a lista completa de cada lado vai cifrada na Mainline DHT. Os dois lados testam todos os pares ao mesmo tempo com probes autenticados (HMAC); quem entra escolhe o melhor par confirmado e faz o handshake Noise NNpsk0 nele. O chat segue sobre o transporte Noise.

**Tech Stack:** Rust 2021, tokio, `portmapper` 0.20 (UPnP/NAT-PMP/PCP), `mainline` 8 (BEP44, API async), `snow` 0.10 (Noise), `if-addrs`, `ring` (HKDF, HMAC, ChaCha20-Poly1305), `argon2`, ratatui/crossterm.

**Spec:** `docs/superpowers/specs/2026-11-20-p2p-sem-infra-design.md`

## Global Constraints

- Nenhum servidor hospedado ou pago pelo projeto. Só STUN público (Google, Cloudflare) e os nós de bootstrap padrão da Mainline DHT. Sem relay/TURN, sem chave de conta paga no binário.
- Mapeamento de porta removido ao sair normalmente (ESC, Ctrl-C, fim). Nunca criar mapeamento permanente.
- Ao abrir porta, mostrar exatamente: `UDP port {port} opened on your router (closed on exit)`.
- Toda a interface em inglês.
- Código v3: `base58(3 || segredo[16] || candidatos diretos)`; segredo de 128 bits; candidatos diretos só `mapped`, até um `ipv6` e até um `lan`.
- Registros na DHT: itens mutáveis BEP44, salts `c` (quem cria) e `j` (quem entra), valor ≤ 1000 bytes, ChaCha20-Poly1305 com nonce aleatório.
- Probes a cada 200 ms, com tag HMAC; `ProbeAck` vai para o endereço de origem do pacote.
- Timeouts: quem cria espera 10 min; quem entra desiste 45 s depois de receber os candidatos de quem criou, ou 60 s se eles nunca chegarem.
- Keepalive a cada 15 s.
- Handshake `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`; PSK derivada do segredo do código e de Argon2id(senha ou `""`, salt derivado do segredo). `-p` opcional.
- Erro de senha/código: exatamente `wrong password or invalid code`.
- Prioridade de caminho: `lan` > `ipv6` > `mapped` > `reflexive` > `peer-reflexive`.
- Toolchain: o `portmapper` exige Rust recente (≥ 1.89); se o build reclamar, `rustup update stable`.
- Commits no estilo do repo (imperativo, inicial maiúscula, ex.: `Add STUN NAT mapping probe`), sem trailer de coautoria.
- O código antigo (`stun::discover_public_endpoint`, `hole_punch.rs`, `KeyExchange`, `CryptoSession`, `SessionInfo`) continua compilando até a Task 10, que o remove. Avisos de código não usado nos módulos novos são esperados até lá.

## Review Focus

1. **Código colado com quebras de linha, espaços ou aspas** (WhatsApp, terminal que quebrou a linha): deve decodificar normalmente. Teste: Task 6, `decode_tolerates_whitespace_and_quotes`.
2. **Teclado no Windows e Ctrl-C dentro do chat:** o crossterm no Windows emite eventos de soltar tecla, e o código atual não filtra, então cada letra sairia duplicada. Ctrl-C em modo raw chega como tecla, não como sinal. Esperado: cada tecla uma vez; Ctrl-C sai como ESC e fecha a porta. Teste: Task 10, `key_action_*`.
3. **Mensagem no limite de tamanho:** datagramas acima de ~1200 bytes se fragmentam e somem em NATs. Esperado: a maior mensagem permitida cabe num datagrama só. Teste: Task 7, `max_text_fits_one_datagram`.
4. **Tráfego estranho na porta da sessão** (scanners batendo na porta aberta no roteador, respostas STUN atrasadas, probes com tag errada): deve ser ignorado sem resposta, e a sessão conecta normalmente. Teste: Task 9, `ignores_junk_and_late_stun`.
5. **Código reutilizado depois que quem criou desistiu:** o registro antigo fica ~2 h na DHT. Esperado: `This session code has expired. Ask your peer for a new one.` na hora, em vez de 45 s de espera e um "No direct path" enganoso. Teste: Task 12, `stale_creator_info_is_expired`.

---

## Mapa de arquivos

| Arquivo | Responsabilidade | Task |
|---|---|---|
| `src/stun.rs` (reescrito) | Consulta STUN async, parsing puro, teste de NAT simétrico | 1 |
| `src/candidates.rs` (novo) | Tipos de candidato, classificação de endereços, interfaces locais, detecção de CGNAT | 2 |
| `src/portmap.rs` (novo) | Wrapper do `portmapper`: abrir, esperar IP externo, sondar, fechar | 3 |
| `src/gather.rs` (novo) | Sockets + coleta completa + `NetSummary` | 4 |
| `src/doctor.rs` (novo) | `whisper doctor`, textos de diagnóstico e de falha | 4, 12 |
| `src/signal.rs` (novo) | Acesso à DHT, cifra dos registros, publicação e consulta | 4, 11 |
| `src/keys.rs` (novo) | Segredo da sessão e derivação de chaves (HKDF, Argon2id) | 5 |
| `src/code.rs` (novo) | Código v3 | 6 |
| `src/wire.rs` (novo) | Formato binário dos pacotes, tags de probe, payload do chat | 7 |
| `src/crypto/mod.rs` (reescrito) | Handshake Noise, `Transport`, janela anti-replay, fingerprint | 8 |
| `src/connect.rs` (novo, substitui `hole_punch.rs`) | Testes de conectividade, handshake, erros de conexão | 9, 12 |
| `src/cli/mod.rs` (modificado) | UI do chat sobre o novo transporte | 10 |
| `src/main.rs` (modificado) | Comandos `create`, `join`, `doctor` | 4, 10, 12, 14 |
| `src/session/mod.rs` (reduzido) | `validate_username`, limites | 10 |
| `examples/stun_responder.rs`, `examples/dht_bootstrap.rs` | Peças do laboratório de NAT | 14 |
| `scripts/natlab.sh`, `.github/workflows/ci.yml` | Simulação de NAT e CI | 15 |

Removidos: `src/hole_punch.rs`, `src/cli/p2p.rs` (Task 10); `P2P_TROUBLESHOOTING.md`, `RELAYS.md`, `DEPLOY.md` (Task 13).

Testes ficam em `#[cfg(test)] mod tests` dentro de cada arquivo, como em `src/crypto/mod.rs` hoje (o crate é só binário).

---

## Fase 1: coleta e diagnóstico

### Task 1: STUN async e teste de NAT simétrico

**Files:**
- Modify: `src/stun.rs`

**Interfaces:**
- Produces:
  - `pub const STUN_SERVERS: &[&str]` = os 5 do Google atuais + `"stun.cloudflare.com:3478"`
  - `#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)] pub enum NatMapping { EndpointIndependent, EndpointDependent, Unknown }`
  - `pub fn build_binding_request(txid: &[u8; 12]) -> [u8; 20]`
  - `pub fn parse_binding_response(buf: &[u8], txid: &[u8; 12]) -> anyhow::Result<SocketAddr>`
  - `pub fn classify_mapping(a: SocketAddr, b: SocketAddr) -> NatMapping`
  - `pub async fn query(socket: &tokio::net::UdpSocket, server: SocketAddr, timeout: Duration) -> anyhow::Result<SocketAddr>`
  - `pub async fn probe_nat(socket: &tokio::net::UdpSocket) -> (Option<SocketAddr>, NatMapping)`

- [ ] **Step 1: Escrever os testes que falham**

```rust
// helper do módulo de testes: monta uma Binding Response (0x0101) com um atributo
// XOR-MAPPED-ADDRESS (0x0020) para `addr` e o `txid` dado.
fn response_for(txid: &[u8; 12], addr: SocketAddrV4) -> Vec<u8> { /* ... */ }

#[test]
fn request_has_header_cookie_and_txid() {
    let r = build_binding_request(&[1; 12]);
    assert_eq!(&r[0..4], &[0x00, 0x01, 0x00, 0x00]);
    assert_eq!(&r[4..8], &[0x21, 0x12, 0xA4, 0x42]);
    assert_eq!(&r[8..20], &[1; 12]);
}

#[test]
fn parses_xor_mapped_address() {
    let txid = [7; 12];
    let addr: SocketAddrV4 = "203.0.113.5:54321".parse().unwrap();
    assert_eq!(parse_binding_response(&response_for(&txid, addr), &txid).unwrap(), SocketAddr::V4(addr));
}

#[test]
fn rejects_wrong_txid_and_short_buffers() {
    let resp = response_for(&[7; 12], "203.0.113.5:1".parse().unwrap());
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
#[ignore] // requer rede
async fn probe_nat_against_public_servers() {
    let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let (addr, _) = probe_nat(&s).await;
    assert!(addr.is_some());
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test stun::`
Expected: falha de compilação (`build_binding_request`, `parse_binding_response`, `classify_mapping` não existem).

- [ ] **Step 3: Implementar**

- Extraia a montagem do pedido e o parsing de `query_stun_server` para `build_binding_request` e `parse_binding_response`. O `query_stun_server` síncrono e o `discover_public_endpoint` passam a usá-las e continuam existindo até a Task 10.
- `query`: envia o pedido, lê com `tokio::time::timeout`, descarta datagramas que não fazem parse com o txid esperado e continua lendo até o timeout.
- `probe_nat`: resolve `stun.l.google.com:19302` e `stun.cloudflare.com:3478` para IPv4 (`tokio::net::lookup_host`) e consulta os dois em sequência, com timeout de 3 s cada.
  - As duas respostas chegaram: `(Some(primeira), classify_mapping(a, b))`.
  - Só uma chegou: `(Some(ela), Unknown)`. Antes de desistir, tente os demais `STUN_SERVERS` para obter ao menos o endereço.
  - Nenhuma chegou: `(None, Unknown)`.
- `serde` já é dependência.

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test stun::`
Expected: 4 testes passam e 1 é ignorado. `cargo build` sem erros.

- [ ] **Step 5: Commit**

```bash
git add src/stun.rs
git commit -m "Add async STUN query and NAT mapping probe"
```

### Task 2: Candidatos e classificação de endereços

**Files:**
- Create: `src/candidates.rs`
- Modify: `src/main.rs` (adicionar `mod candidates;`), `Cargo.toml` (`cargo add if-addrs`)

**Interfaces:**
- Produces:
  - `#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)] pub enum CandidateKind { Lan, Ipv6, Mapped, Reflexive, PeerReflexive }`
  - `impl CandidateKind { pub fn priority(self) -> u8 }`: Lan 5, Ipv6 4, Mapped 3, Reflexive 2, PeerReflexive 1
  - `impl std::fmt::Display for CandidateKind`: `lan`, `ipv6`, `mapped`, `reflexive`, `peer-reflexive`
  - `#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct Candidate { pub kind: CandidateKind, pub addr: SocketAddr }`
  - `#[derive(Debug, PartialEq, Eq)] pub enum V4Class { Public, Private, Cgnat, Loopback, LinkLocal, Unspecified }`
  - `pub fn classify_v4(ip: Ipv4Addr) -> V4Class`
  - `pub fn is_global_v6(ip: &Ipv6Addr) -> bool`: só `2000::/3`
  - `pub fn interface_addrs() -> Vec<IpAddr>`: via `if_addrs::get_if_addrs()`, sem loopback
  - `pub fn primary_v4() -> Option<Ipv4Addr>`: `UdpSocket::bind("0.0.0.0:0")` + `connect("8.8.8.8:80")` + `local_addr()`. Não envia pacote.
  - `pub fn local_candidates(addrs: &[IpAddr], v4_port: u16, v6_port: Option<u16>) -> Vec<Candidate>`: `Lan` só para `V4Class::Private` (máx. 2, na ordem recebida); `Ipv6` só para `is_global_v6` (máx. 3, e só se `v6_port` for `Some`)
  - `pub fn mapped_candidate(ext: Option<SocketAddrV4>) -> Option<Candidate>`: `Some` só se o IP for `Public`
  - `pub fn detect_cgnat(primary: Option<Ipv4Addr>, router_ext: Option<Ipv4Addr>, stun_ip: Option<Ipv4Addr>) -> Option<bool>`
  - `pub fn infer_kind(addr: SocketAddr) -> CandidateKind`: IPv6 → `Ipv6`; IPv4 privado → `Lan`; IPv4 público → `Mapped`
  - `pub fn select_direct(cands: &[Candidate]) -> Vec<SocketAddr>`: o `Mapped`, o primeiro `Ipv6` e o primeiro `Lan`, nessa ordem, no máximo 3

- [ ] **Step 1: Escrever os testes que falham**

```rust
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
    let c = local_candidates(&addrs, 4000, Some(5000));
    let lan: Vec<_> = c.iter().filter(|c| c.kind == CandidateKind::Lan).map(|c| c.addr).collect();
    assert_eq!(lan, vec!["192.168.0.10:4000".parse().unwrap(), "10.0.0.5:4000".parse().unwrap()]);
    assert_eq!(c.iter().filter(|c| c.kind == CandidateKind::Ipv6).count(), 3);
    assert!(c.iter().all(|c| c.addr.ip() != "100.100.1.1".parse::<IpAddr>().unwrap()));
    assert!(local_candidates(&addrs, 4000, None).iter().all(|c| c.kind == CandidateKind::Lan));
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
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test candidates::`
Expected: falha de compilação (módulo vazio).

- [ ] **Step 3: Implementar `src/candidates.rs` com as assinaturas acima**

Regras do `detect_cgnat`, na ordem:
1. `primary` em `Cgnat` → `Some(true)`.
2. Se há `router_ext`: se for `Cgnat` ou `Private` → `Some(true)`; senão, se `stun_ip` for `Some` e diferente de `router_ext` → `Some(true)`; senão → `Some(false)`.
3. Sem `router_ext`: `primary` `Public` e igual a `stun_ip` → `Some(false)`; qualquer outro caso → `None`.

Endereços `Cgnat` nunca viram `Lan`. Isso evita, por exemplo, endereços do Tailscale (100.x).

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test candidates::`
Expected: 6 testes passam.

- [ ] **Step 5: Commit**

```bash
git add src/candidates.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "Add connection candidates and address classification"
```

### Task 3: Abertura de porta no roteador

**Files:**
- Create: `src/portmap.rs`
- Modify: `src/main.rs` (`mod portmap;`), `Cargo.toml` (`cargo add portmapper@0.20`)

**Interfaces:**
- Produces:
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct ProbeFlags { pub upnp: bool, pub nat_pmp: bool, pub pcp: bool }`
  - `pub struct PortMap { client: portmapper::Client }`
  - `impl PortMap { pub fn start(local_port: u16) -> Self }`: `Client::default()`, `update_local_port(NonZeroU16)`, `procure_mapping()`
  - `pub async fn wait_external(&self, timeout: Duration) -> Option<SocketAddrV4>`: espera o primeiro `Some` em `watch_external_address()`
  - `pub async fn probe(&self, timeout: Duration) -> Option<ProbeFlags>`: a partir de `client.probe()`, que devolve `ProbeOutput { upnp, pcp, nat_pmp }`
  - `pub async fn close(self)`: `deactivate()` e depois espera o watcher virar `None`, por no máximo 2 s
  - `impl Drop for PortMap`: chama `deactivate()` (melhor esforço quando ninguém chama `close`)

- [ ] **Step 1: Escrever o teste que falha**

```rust
#[tokio::test]
async fn close_completes_within_three_seconds() {
    let pm = PortMap::start(40_123);
    let _ = pm.wait_external(Duration::from_millis(500)).await;
    let t = std::time::Instant::now();
    pm.close().await;
    assert!(t.elapsed() < Duration::from_secs(3));
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test portmap::`
Expected: falha de compilação.

- [ ] **Step 3: Implementar `src/portmap.rs`**

Se o build reclamar da versão do Rust, rode `rustup update stable` (ver Global Constraints).

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test portmap::`
Expected: PASS. Numa rede com UPnP, o teste abre e fecha de verdade a porta 40123, o que é esperado.

- [ ] **Step 5: Commit**

```bash
git add src/portmap.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "Add router port mapping via portmapper"
```

### Task 4: Coleta completa e `whisper doctor`

**Files:**
- Create: `src/gather.rs`, `src/doctor.rs`, `src/signal.rs` (só `public_dht` por enquanto)
- Modify: `src/main.rs` (módulos + subcomando `Doctor`), `Cargo.toml` (`cargo add mainline@8`)

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces:
  - `gather.rs`:
    - `pub struct Sockets { pub v4: tokio::net::UdpSocket, pub v6: Option<tokio::net::UdpSocket> }`
    - `pub async fn bind_sockets(has_global_v6: bool) -> anyhow::Result<Sockets>`: v4 em `0.0.0.0:0`; v6 em `[::]:0` só se `has_global_v6` e o bind der certo
    - `#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)] pub struct NetSummary { pub ipv6: bool, pub mapped: bool, pub cgnat: Option<bool>, pub nat: NatMapping }`
    - `impl NetSummary { pub fn can_host(&self) -> bool }`: `ipv6 || mapped`
    - `pub struct Gathered { pub sockets: Sockets, pub candidates: Vec<Candidate>, pub summary: NetSummary, pub portmap: Option<PortMap>, pub probe: Option<ProbeFlags>, pub router_ext: Option<SocketAddrV4>, pub stun_addr: Option<SocketAddr>, pub ipv6_addr: Option<Ipv6Addr> }`
    - `impl Gathered { pub fn mapped_port(&self) -> Option<u16> }`
    - `pub async fn gather() -> anyhow::Result<Gathered>`
  - `signal.rs`: `pub fn public_dht() -> std::io::Result<mainline::async_dht::AsyncDht>` (`Dht::client()?.as_async()`)
  - `doctor.rs`:
    - `pub struct DoctorReport { pub ipv6: Option<Ipv6Addr>, pub probe: Option<ProbeFlags>, pub router_ext: Option<Ipv4Addr>, pub stun_ip: Option<Ipv4Addr>, pub summary: NetSummary, pub dht: Option<Duration> }`
    - `pub fn mask_v4(ip: Ipv4Addr) -> String`, `pub fn mask_v6(ip: Ipv6Addr) -> String`, `pub fn verdict(s: &NetSummary) -> &'static str`, `pub fn render(r: &DoctorReport) -> String`
    - `pub async fn run() -> anyhow::Result<()>`

- [ ] **Step 1: Escrever os testes que falham**

Em `gather.rs`:

```rust
#[test]
fn can_host_with_ipv6_or_mapping() {
    let s = |ipv6, mapped| NetSummary { ipv6, mapped, cgnat: None, nat: NatMapping::Unknown };
    assert!(s(true, false).can_host());
    assert!(s(false, true).can_host());
    assert!(!s(false, false).can_host());
}
```

Em `doctor.rs`:

```rust
#[test]
fn masks_addresses() {
    assert_eq!(mask_v4("189.40.12.34".parse().unwrap()), "189.40.x.x");
    assert_eq!(mask_v6("2804:14c:65a1::1".parse().unwrap()), "2804:14c:…");
}

#[test]
fn verdicts() {
    let s = |ipv6, mapped, nat| NetSummary { ipv6, mapped, cgnat: None, nat };
    use NatMapping::*;
    assert_eq!(verdict(&s(false, true, Unknown)), "can host sessions");
    assert_eq!(verdict(&s(true, false, Unknown)), "can likely reach peers that have IPv6");
    assert_eq!(verdict(&s(false, false, EndpointIndependent)), "cannot host; hole punching likely works");
    assert_eq!(verdict(&s(false, false, EndpointDependent)), "direct connections unlikely from this network");
}

#[test]
fn renders_report() {
    let r = DoctorReport {
        ipv6: Some("2804:14c:65a1::1".parse().unwrap()),
        probe: Some(ProbeFlags { upnp: true, nat_pmp: false, pcp: false }),
        router_ext: Some("189.40.12.34".parse().unwrap()),
        stun_ip: Some("189.40.12.34".parse().unwrap()),
        summary: NetSummary { ipv6: true, mapped: true, cgnat: Some(false), nat: NatMapping::EndpointIndependent },
        dht: Some(Duration::from_millis(2100)),
    };
    assert_eq!(render(&r), "\
Global IPv6:   yes (2804:14c:…)
Router:        UPnP yes   NAT-PMP no   PCP no   external IP 189.40.x.x
CGNAT:         no
NAT mapping:   endpoint-independent (good for hole punching)
DHT:           reachable (2.1 s)
Verdict:       can host sessions
");
}
```

Variantes de linha que o `render` também precisa produzir:
- `Global IPv6:   no`
- `Router:        no port mapping protocol found`
- `CGNAT:         yes` ou `CGNAT:         unknown`
- `NAT mapping:   symmetric (hole punching unlikely)` ou `NAT mapping:   unknown (STUN unreachable)`
- `DHT:           unreachable`

O `verdict` testa as condições na ordem: `mapped`, `ipv6`, NAT `EndpointIndependent`, resto.

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test gather:: doctor::`
Expected: falha de compilação.

- [ ] **Step 3: Implementar `gather()`**

1. `interface_addrs()` e `primary_v4()`.
2. `bind_sockets(algum endereço global v6)`.
3. `PortMap::start(porta v4)`.
4. Em paralelo (`tokio::join!`): `stun::probe_nat(&v4)`, `pm.wait_external(3 s)`, `pm.probe(3 s)`.
5. Candidatos: `local_candidates`, mais `mapped_candidate(ext)`, mais `Reflexive` (endereço do STUN, se houver).
6. `summary`: `cgnat` vem de `detect_cgnat(primary, ext.ip, stun.ip)`.
7. Se não houver candidato `Mapped`, chame `pm.close().await` antes de retornar e devolva `portmap: None`, para não deixar mapeamento inútil (NAT duplo).

- [ ] **Step 4: Implementar `doctor::run()` e o subcomando**

- `run()`: `gather()`, depois teste da DHT (`public_dht()`, `tokio::time::timeout(10 s, dht.bootstrapped())`, medindo o tempo), monta o `DoctorReport`, imprime `render`, fecha o `portmap` se houver.
- Em `main.rs`, adicione `Doctor` ao enum `Commands`, com a doc `/// Check whether this network can host or join sessions`. `create` e `join` não mudam nesta task.

- [ ] **Step 5: Rodar os testes e o comando**

Run: `cargo test gather:: doctor::`
Expected: 4 testes passam.

Run: `cargo run -- doctor`
Expected: 6 linhas no formato acima, com valores reais da sua rede. O comando termina em até ~15 s.

- [ ] **Step 6: Commit**

```bash
git add src/gather.rs src/doctor.rs src/signal.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "Add network gathering and whisper doctor"
```

---

## Fase 2: conexão direta

### Task 5: Segredo da sessão e derivação de chaves

**Files:**
- Create: `src/keys.rs`
- Modify: `src/main.rs` (`mod keys;`)

**Interfaces:**
- Produces:
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct SessionSecret(pub [u8; 16]);` com `pub fn generate() -> Self`
  - `#[derive(Clone)] pub struct SessionKeys { pub dht_seed: [u8; 32], pub record_key: [u8; 32], pub probe_key: [u8; 32], pub argon_salt: [u8; 16], pub psk_base: [u8; 32] }`
  - `impl SessionKeys { pub fn derive(secret: &SessionSecret) -> Self }`
  - `pub fn derive_psk(keys: &SessionKeys, password: &str) -> [u8; 32]`

- [ ] **Step 1: Escrever os testes que falham**

```rust
#[test]
fn derivation_is_deterministic_and_separated() {
    let s = SessionSecret([9; 16]);
    let (a, b) = (SessionKeys::derive(&s), SessionKeys::derive(&s));
    assert_eq!(a.dht_seed, b.dht_seed);
    let outs = [a.dht_seed, a.record_key, a.probe_key, a.psk_base];
    for i in 0..outs.len() { for j in i + 1..outs.len() { assert_ne!(outs[i], outs[j]); } }
    assert_ne!(SessionKeys::derive(&SessionSecret([1; 16])).dht_seed, a.dht_seed);
}

#[test]
fn psk_depends_on_password_and_allows_empty() {
    let k = SessionKeys::derive(&SessionSecret([9; 16]));
    assert_eq!(derive_psk(&k, ""), derive_psk(&k, ""));
    assert_ne!(derive_psk(&k, ""), derive_psk(&k, "secret"));
    assert_ne!(derive_psk(&k, "a"), derive_psk(&k, "b"));
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test keys::`
Expected: falha de compilação.

- [ ] **Step 3: Implementar**

- HKDF-SHA256 do `ring` (`ring::hkdf`), com salt vazio e o segredo como IKM.
- Rótulos `info`, um por saída: `whisper/v3/dht`, `whisper/v3/record`, `whisper/v3/probe`, `whisper/v3/argon-salt`, `whisper/v3/psk-base`.
- `derive_psk`: `Argon2::default().hash_password_into(password, argon_salt, 32 bytes)`. Depois HKDF com IKM = `psk_base || argon_out` e `info` = `whisper/v3/psk`.

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test keys::`
Expected: 2 testes passam.

- [ ] **Step 5: Commit**

```bash
git add src/keys.rs src/main.rs
git commit -m "Add session secret and key derivation"
```

### Task 6: Código de sessão v3

**Files:**
- Create: `src/code.rs`
- Modify: `src/main.rs` (`mod code;`)

**Interfaces:**
- Consumes: `SessionSecret` (Task 5).
- Produces:
  - `pub const CODE_VERSION: u8 = 3;`, `pub const MAX_DIRECT: usize = 3;`
  - `#[derive(Debug, PartialEq)] pub struct SessionCode { pub secret: SessionSecret, pub direct: Vec<SocketAddr> }`
  - `impl SessionCode { pub fn encode(&self) -> String; pub fn decode(s: &str) -> anyhow::Result<Self> }`

Layout binário (antes do base58):
- `[3]`, `segredo (16)`, `n (1)`, e `n` endereços.
- Cada endereço é `[4] ip(4) porta(2, BE)` ou `[6] ip(16) porta(2, BE)`.

- [ ] **Step 1: Escrever os testes que falham**

```rust
fn sample() -> SessionCode {
    SessionCode { secret: SessionSecret([5; 16]), direct: vec![
        "189.40.1.2:40000".parse().unwrap(),
        "[2804:14c:65a1:4321:abcd:ef01:2345:6789]:41000".parse().unwrap(),
        "192.168.0.10:40000".parse().unwrap()] }
}

#[test]
fn roundtrip_with_and_without_direct() {
    let c = sample();
    assert_eq!(SessionCode::decode(&c.encode()).unwrap(), c);
    let bare = SessionCode { secret: SessionSecret([5; 16]), direct: vec![] };
    assert_eq!(SessionCode::decode(&bare.encode()).unwrap(), bare);
    assert!(bare.encode().len() <= 30);
    assert!(c.encode().len() <= 90);
}

#[test]
fn decode_tolerates_whitespace_and_quotes() {
    let e = sample().encode();
    let (a, b) = e.split_at(20);
    for pasted in [format!("  {e}\n"), format!("\"{e}\""), format!("`{a}\n{b}`"), format!("{a} {b}")] {
        assert_eq!(SessionCode::decode(&pasted).unwrap(), sample());
    }
}

#[test]
fn rejects_old_truncated_and_foreign_codes() {
    let old = SessionCode::decode("203.45.67.89:54321#7kJ9xnYpQm#QgT98sXCthe3").unwrap_err();
    assert!(old.to_string().contains("older whisper version"));
    let e = sample().encode();
    assert!(SessionCode::decode(&e[..e.len() - 4]).unwrap_err().to_string().contains("copied all of it"));
    let mut bytes = bs58::decode(&e).into_vec().unwrap();
    bytes.truncate(bytes.len() - 3);
    assert!(SessionCode::decode(&bs58::encode(&bytes).into_string()).unwrap_err().to_string().contains("copied all of it"));
    let mut v2 = bs58::decode(&e).into_vec().unwrap();
    v2[0] = 2;
    assert!(SessionCode::decode(&bs58::encode(v2).into_string()).unwrap_err().to_string().contains("copied all of it"));
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test code::`
Expected: falha de compilação.

- [ ] **Step 3: Implementar**

- Antes de decodificar, remova todo caractere de espaço em branco (em qualquer posição) e as aspas `"`, `'` e `` ` `` das pontas.
- Mensagens de erro (exatas):
  - Contém `#`: `This code is from an older whisper version (0.2). Ask your peer to update and create a new session.`
  - Qualquer outra falha (base58 inválido, versão diferente de 3, tamanho errado, `n > MAX_DIRECT`): `Invalid session code. Check that you copied all of it and that you both run the latest whisper.`
- Uma mensagem única para versão errada e para código cortado é intencional. Cortar uma string base58 muda todos os bytes decodificados, inclusive o de versão, então não dá para distinguir os dois casos.

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test code::`
Expected: 3 testes passam.

- [ ] **Step 5: Commit**

```bash
git add src/code.rs src/main.rs
git commit -m "Add v3 session code format"
```

### Task 7: Formato dos pacotes

**Files:**
- Create: `src/wire.rs`
- Modify: `src/main.rs` (`mod wire;`)

**Interfaces:**
- Produces:
  - `pub const MAX_DATAGRAM: usize = 1200;`
  - `pub const T_PROBE: u8 = 0xA1; pub const T_PROBE_ACK: u8 = 0xA2; pub const T_HS1: u8 = 0xA3; pub const T_HS2: u8 = 0xA4; pub const T_DATA: u8 = 0xA5;`
    - O primeiro byte ≥ 0xA0 nunca coincide com STUN (RFC 7983).
  - `#[derive(Debug, PartialEq)] pub enum Packet<'a> { Probe { txid: [u8; 12], tag: [u8; 16] }, ProbeAck { txid: [u8; 12], tag: [u8; 16] }, Hs1(&'a [u8]), Hs2(&'a [u8]), Data { nonce: u64, ciphertext: &'a [u8] } }`
  - `impl<'a> Packet<'a> { pub fn encode(&self) -> Vec<u8>; pub fn decode(buf: &'a [u8]) -> Option<Self> }`
    - Probe/ProbeAck: `[tipo][txid 12][tag 16]` (exatamente 29 bytes).
    - Data: `[tipo][nonce u64 BE][ciphertext]`.
    - Hs1/Hs2: `[tipo][bytes]`.
  - `pub fn probe(probe_key: &[u8; 32], txid: [u8; 12]) -> Packet<'static>` e `pub fn probe_ack(probe_key: &[u8; 32], txid: [u8; 12]) -> Packet<'static>`
    - `tag = HMAC-SHA256(probe_key, [tipo] || txid)[..16]` (`ring::hmac`).
  - `pub fn verify(probe_key: &[u8; 32], p: &Packet) -> bool`: comparação em tempo constante (`subtle`); `false` para tipos que não são probe.
  - `#[derive(Debug, PartialEq)] pub enum ChatPayload { Text(String), Ping, Pong, Bye }`
  - `impl ChatPayload { pub fn encode(&self) -> Vec<u8>; pub fn decode(b: &[u8]) -> Option<Self> }`: `[0][utf8]`, `[1]`, `[2]`, `[3]`

- [ ] **Step 1: Escrever os testes que falham**

```rust
const K: [u8; 32] = [3; 32];

#[test]
fn packets_roundtrip() {
    for p in [probe(&K, [1; 12]), probe_ack(&K, [2; 12]), Packet::Hs1(b"abc"), Packet::Hs2(b"def"),
              Packet::Data { nonce: 7, ciphertext: b"xyz" }] {
        assert_eq!(Packet::decode(&p.encode()), Some(p));
    }
}

#[test]
fn rejects_stun_junk_and_bad_lengths() {
    let stun = crate::stun::build_binding_request(&[0; 12]);
    assert_eq!(Packet::decode(&stun), None);
    assert_eq!(Packet::decode(&[]), None);
    assert_eq!(Packet::decode(&[T_PROBE, 1, 2]), None);
    assert_eq!(Packet::decode(&[T_DATA, 0, 0]), None);
}

#[test]
fn probe_tags_are_keyed_and_typed() {
    let p = probe(&K, [1; 12]);
    assert!(verify(&K, &p));
    assert!(!verify(&[4; 32], &p));
    let Packet::Probe { txid, tag } = p else { unreachable!() };
    assert!(!verify(&K, &Packet::ProbeAck { txid, tag }));
}

#[test]
fn chat_payload_roundtrip_and_invalid_utf8() {
    for p in [ChatPayload::Text("olá".into()), ChatPayload::Ping, ChatPayload::Pong, ChatPayload::Bye] {
        assert_eq!(ChatPayload::decode(&p.encode()), Some(p));
    }
    assert_eq!(ChatPayload::decode(&[0, 0xFF, 0xFE]), None);
}

#[test]
fn max_text_fits_one_datagram() {
    let text = "a".repeat(crate::session::MAX_MESSAGE_LEN);
    let plain = ChatPayload::Text(text).encode();
    let ct = vec![0u8; plain.len() + 16]; // tag do ChaChaPoly
    assert!(Packet::Data { nonce: u64::MAX, ciphertext: &ct }.encode().len() <= MAX_DATAGRAM);
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test wire::`
Expected: falha de compilação.

- [ ] **Step 3: Implementar `src/wire.rs` e mudar `MAX_MESSAGE_LEN` para `1000` em `src/session/mod.rs`**

`MAX_MESSAGE_LEN` passa a ser medido em bytes UTF-8. O limite antigo de 4096 geraria datagramas fragmentados.

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test wire::`
Expected: 5 testes passam.

- [ ] **Step 5: Commit**

```bash
git add src/wire.rs src/main.rs src/session/mod.rs
git commit -m "Add binary wire format with authenticated probes"
```

### Task 8: Handshake Noise e transporte

**Files:**
- Modify: `src/crypto/mod.rs` (adicionar; `KeyExchange` e `CryptoSession` ficam até a Task 10), `Cargo.toml` (`cargo add snow@0.10`)

**Interfaces:**
- Produces:
  - `pub const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";`
  - `pub fn initiator(psk: &[u8; 32]) -> anyhow::Result<snow::HandshakeState>` e `pub fn responder(psk: &[u8; 32]) -> anyhow::Result<snow::HandshakeState>`
    - Ambos usam `Builder::new(NOISE_PARAMS.parse()?).psk(0, psk)?`.
  - `pub struct Transport { state: snow::StatelessTransportState, send_nonce: AtomicU64, replay: Mutex<ReplayWindow> }`
  - `impl Transport { pub fn from_handshake(hs: snow::HandshakeState) -> anyhow::Result<(Self, String)> }`
    - O `String` é o `session_fingerprint` do hash do handshake.
    - Leia `get_handshake_hash()` antes de `into_stateless_transport_mode()`.
  - `pub fn seal(&self, plaintext: &[u8]) -> anyhow::Result<(u64, Vec<u8>)>`
  - `pub fn open(&self, nonce: u64, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>>`: rejeita replay
  - `pub struct ReplayWindow { highest: Option<u64>, bitmap: u64 }`
    - `pub fn new() -> Self`
    - `pub fn accept(&mut self, nonce: u64) -> bool`: janela de 64, como no WireGuard
  - `pub fn session_fingerprint(hash: &[u8]) -> String`: 16 primeiros bytes em hex maiúsculo, 4 grupos de 8 separados por espaço (mesmo formato do `fingerprint` atual)

- [ ] **Step 1: Escrever os testes que falham**

```rust
// helper: roda o handshake em memória; payload da msg1 = "bob", da msg2 = "alice"
fn handshake(psk_i: [u8; 32], psk_r: [u8; 32]) -> anyhow::Result<((Transport, String), (Transport, String))> { /* ... */ }

#[test]
fn same_psk_completes_with_matching_fingerprints() {
    let ((ti, fi), (tr, fr)) = handshake([1; 32], [1; 32]).unwrap();
    assert_eq!(fi, fr);
    let (n, ct) = ti.seal(b"oi").unwrap();
    assert_eq!(tr.open(n, &ct).unwrap(), b"oi");
    let (n, ct) = tr.seal(b"tchau").unwrap();
    assert_eq!(ti.open(n, &ct).unwrap(), b"tchau");
}

#[test]
fn different_psk_fails() {
    assert!(handshake([1; 32], [2; 32]).is_err());
}

#[test]
fn replayed_packet_is_rejected() {
    let ((ti, _), (tr, _)) = handshake([1; 32], [1; 32]).unwrap();
    let (n, ct) = ti.seal(b"x").unwrap();
    assert!(tr.open(n, &ct).is_ok());
    assert!(tr.open(n, &ct).is_err());
}

#[test]
fn replay_window_accepts_reordering_within_64() {
    let mut w = ReplayWindow::new();
    assert!(w.accept(10));
    assert!(w.accept(8));
    assert!(!w.accept(8));
    assert!(w.accept(100));
    assert!(!w.accept(30)); // fora da janela
    assert!(w.accept(99));
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test crypto::`
Expected: falha de compilação nos testes novos.

- [ ] **Step 3: Implementar**

Atenção à ordem dos parâmetros no `snow` 0.10: em `StatelessTransportState::read_message(nonce, payload, message)`, o primeiro buffer é o cifrado e o segundo é a saída. Confira no código-fonte do crate.

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test crypto::`
Expected: os 4 testes novos e os antigos passam.

- [ ] **Step 5: Commit**

```bash
git add src/crypto/mod.rs Cargo.toml Cargo.lock
git commit -m "Add Noise NNpsk0 handshake and replay-protected transport"
```

### Task 9: Testes de conectividade e handshake

**Files:**
- Create: `src/connect.rs`
- Modify: `src/main.rs` (`mod connect;`)

**Interfaces:**
- Consumes:
  - `Sockets`, `NetSummary` (Task 4)
  - `Candidate`, `CandidateKind`, `infer_kind` (Task 2)
  - `SessionKeys` (Task 5)
  - `Packet`, `probe`, `probe_ack`, `verify`, `ChatPayload` (Task 7)
  - `initiator`, `responder`, `Transport` (Task 8)
  - `validate_username`
- Produces:
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Role { Creator, Joiner }`
  - `#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)] pub struct PeerInfo { pub candidates: Vec<Candidate>, pub summary: NetSummary, pub published_ms: i64 }`
  - `#[derive(Clone, Copy, Debug)] pub struct Timeouts { pub probe_interval: Duration, pub tiebreak: Duration, pub hs_retry: Duration, pub wrong_password_after: Duration, pub creator_wait: Duration, pub joiner_with_remote: Duration, pub joiner_without_remote: Duration }`
    - `Default`: 200 ms, 300 ms, 500 ms, 5 s, 600 s, 45 s, 60 s.
  - `pub struct ConnectArgs<'a> { pub role: Role, pub keys: &'a SessionKeys, pub psk: [u8; 32], pub username: &'a str, pub initial_remote: Vec<Candidate>, pub timeouts: Timeouts }`
  - `pub struct Connection { pub socket: std::net::UdpSocket, pub peer: SocketAddr, pub path: CandidateKind, pub transport: Arc<Transport>, pub peer_username: String, pub fingerprint: String }`
  - `#[derive(Debug)] pub enum ConnectError { NoOneJoined, WrongPassword, NoPath { remote: Option<NetSummary> }, Io(std::io::Error) }`, com `Display`:
    - `NoOneJoined`: `No one joined within 10 minutes. Create a new session to try again.`
    - `WrongPassword`: `wrong password or invalid code`
    - `NoPath`: `No direct path to the other peer.`
    - `Io`: o erro de I/O.
  - `pub async fn connect(sockets: Sockets, args: ConnectArgs<'_>, remote_rx: tokio::sync::mpsc::Receiver<PeerInfo>) -> Result<Connection, ConnectError>`

**Algoritmo:** escreva este comportamento; o resto é livre.

- **Candidatos remotos:** começam em `initial_remote`. Cada `PeerInfo` recebido acrescenta os candidatos dele, sem duplicar endereço e mantendo o tipo de maior prioridade. Se o canal fechar (`None`), pare de consultá-lo, sem loop ocupado.
- **A cada `probe_interval`:** envie `probe(probe_key, txid aleatório)` para cada candidato remoto, pelo socket da mesma família (pule IPv6 se `v6` for `None`). Guarde `txid → (endereço, instante)`; descarte entradas com mais de 5 s.
- **Ao receber:**
  - Decodifique e descarte em silêncio tudo que não fizer parse ou não passar em `verify` (probes).
  - `Probe` válido de `src`: responda `probe_ack` com o mesmo txid para `src`. Se `src` não estiver na lista, acrescente-o como `PeerReflexive`.
  - `ProbeAck` válido de `src` com txid conhecido: marque `src` como confirmado.
- **Quem entra (decide o caminho):**
  - No primeiro par confirmado, espere `tiebreak` e escolha o confirmado de maior `priority()`.
  - Envie `Hs1` (mensagem 1 do Noise; payload = próprio username), reenviando os mesmos bytes a cada `hs_retry`.
  - Ao receber `Hs2` do caminho escolhido: termine o handshake (o payload é o username de quem criou, validado), envie três `Data` com `ChatPayload::Ping` e retorne a `Connection`.
  - Se passar `wrong_password_after` desde o primeiro `Hs1` sem `Hs2` válido, retorne `WrongPassword`.
- **Quem cria:**
  - Ao receber `Hs1` de `src`:
    - Mesmos bytes do `Hs1` já aceito: reenvie o `Hs2` guardado.
    - Senão: `responder(psk)` e `read_message`. Se falhar, imprima uma vez `Someone tried to join with the wrong password.` e continue esperando. Se der certo, valide o username, escreva o `Hs2` (payload = próprio username), guarde `(hs1, hs2, transport, src)` e envie o `Hs2`.
  - Retorne a `Connection` quando chegar de `src` o primeiro `Data` que `open` aceitar.
- **Prazos:**
  - Quem cria: `NoOneJoined` após `creator_wait`.
  - Os dois lados: quando chega o primeiro `PeerInfo`, o prazo vira `chegada + joiner_with_remote`; ao estourar, `NoPath { remote: Some(summary) }`.
  - Quem entra sem `PeerInfo`: `NoPath { remote: None }` após `joiner_without_remote`.
- **Ao retornar:** converta o socket escolhido com `into_std()`. O outro socket é descartado.

- [ ] **Step 1: Escrever os testes que falham**

Todos em loopback, com `Timeouts` curtos: `probe_interval` 50 ms, `tiebreak` 50 ms, `hs_retry` 100 ms, `wrong_password_after` 1 s, `creator_wait` 3 s, `joiner_with_remote` 2 s, `joiner_without_remote` 2 s.

```rust
// helpers: loopback_sockets() -> (Sockets, SocketAddr) com v4 em 127.0.0.1:0 e v6 None;
// closed_rx() -> Receiver cujo Sender já foi descartado;
// args(role, keys, psk, name, initial) com os Timeouts curtos.

#[tokio::test]
async fn connects_over_loopback() {
    let keys = SessionKeys::derive(&SessionSecret([1; 16]));
    let psk = derive_psk(&keys, "");
    let (cs, caddr) = loopback_sockets().await;
    let (js, _) = loopback_sockets().await;
    let creator = connect(cs, args(Role::Creator, &keys, psk, "alice", vec![]), closed_rx());
    let joiner = connect(js, args(Role::Joiner, &keys, psk, "bob",
        vec![Candidate { kind: CandidateKind::Lan, addr: caddr }]), closed_rx());
    let (c, j) = tokio::join!(creator, joiner);
    let (c, j) = (c.unwrap(), j.unwrap());
    assert_eq!((c.peer_username.as_str(), j.peer_username.as_str()), ("bob", "alice"));
    assert_eq!(c.fingerprint, j.fingerprint);
    assert_eq!(j.path, CandidateKind::Lan);
}

#[tokio::test]
async fn wrong_password_is_reported() {
    // mesmo segredo; o criador usa derive_psk(&keys, "a"), quem entra derive_psk(&keys, "b")
    // espera: joiner == Err(WrongPassword) em menos de 2 s; criador continua esperando
}

#[tokio::test]
async fn remote_candidates_arrive_via_channel() {
    // quem entra começa sem candidatos; 300 ms depois chega um PeerInfo com o candidato
    // do criador num canal aberto; espera: os dois conectam
}

#[tokio::test]
async fn unreachable_peer_gives_no_path() {
    // quem entra recebe PeerInfo com candidato 127.0.0.1:9 e ninguém escutando
    // espera: Err(NoPath { remote: Some(_) }) depois de ~2 s
}

#[tokio::test]
async fn creator_gives_up_after_wait() {
    // criador sozinho; espera: Err(NoOneJoined) depois de ~3 s
}

#[tokio::test]
async fn ignores_junk_and_late_stun() {
    // antes de quem entra começar, um terceiro socket manda para o criador:
    // 64 bytes aleatórios, uma Binding Response STUN e um Probe com tag de outra chave.
    // espera: conexão normal depois; o terceiro socket não recebe nada em 500 ms
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test connect::`
Expected: falha de compilação.

- [ ] **Step 3: Implementar `src/connect.rs`**

Use `tokio::select!` sobre: recebimento no v4, recebimento no v6 (se houver), o tick de probes, o tick de reenvio do `Hs1`, `remote_rx.recv()` (enquanto aberto) e o prazo.

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test connect::`
Expected: 6 testes passam, em menos de ~15 s no total.

- [ ] **Step 5: Commit**

```bash
git add src/connect.rs src/main.rs
git commit -m "Add two-sided connectivity checks and Noise handshake"
```

### Task 10: Ligar `create`/`join` ao novo fluxo e adaptar o chat

**Files:**
- Modify:
  - `src/main.rs`: reescrever `create_session` e `join_session`; `password: Option<String>`
  - `src/cli/mod.rs`: chat sobre `Connection`
  - `src/session/mod.rs`: deixar só `validate_username`, `MAX_USERNAME_LEN`, `MAX_MESSAGE_LEN`
  - `src/stun.rs`: remover `discover_public_endpoint` e `query_stun_server`
  - `src/crypto/mod.rs`: remover `KeyExchange`, `CryptoSession`, `fingerprint`
  - `Cargo.toml`: remover `x25519-dalek`, `rand_core`, `sha2` se não houver mais uso (`grep -rn` antes)
- Delete: `src/hole_punch.rs`, `src/cli/p2p.rs`

**Interfaces:**
- Consumes: Tasks 2 a 9.
- Produces:
  - `cli/mod.rs`:
    - `impl P2PChat { pub fn new(username: String, conn: Connection) -> Self; pub fn run(&mut self) -> anyhow::Result<()> }`
    - `pub enum KeyAction { Quit, Send, Backspace, Char(char), Ignore }`
    - `pub fn key_action(key: crossterm::event::KeyEvent) -> KeyAction`
  - `main.rs`: `async fn run_session(role: Role, username: &str, password: Option<&str>, gathered: Gathered, keys: SessionKeys, initial_remote: Vec<Candidate>, remote_rx: mpsc::Receiver<PeerInfo>) -> anyhow::Result<()>`. A Task 12 passa o `remote_rx` da DHT para cá.

- [ ] **Step 1: Escrever os testes que falham (em `cli/mod.rs`)**

```rust
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
fn ev(code: KeyCode, mods: KeyModifiers, kind: KeyEventKind) -> KeyEvent {
    KeyEvent { code, modifiers: mods, kind, state: KeyEventState::NONE }
}

#[test]
fn key_action_ignores_release_events() {
    assert!(matches!(key_action(ev(KeyCode::Char('a'), KeyModifiers::NONE, KeyEventKind::Release)), KeyAction::Ignore));
    assert!(matches!(key_action(ev(KeyCode::Char('a'), KeyModifiers::NONE, KeyEventKind::Press)), KeyAction::Char('a')));
}

#[test]
fn key_action_ctrl_c_and_esc_quit() {
    assert!(matches!(key_action(ev(KeyCode::Char('c'), KeyModifiers::CONTROL, KeyEventKind::Press)), KeyAction::Quit));
    assert!(matches!(key_action(ev(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Press)), KeyAction::Quit));
    assert!(matches!(key_action(ev(KeyCode::Char('c'), KeyModifiers::NONE, KeyEventKind::Press)), KeyAction::Char('c')));
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test cli::`
Expected: falha de compilação.

- [ ] **Step 3: Implementar o chat**

O chat mantém a estrutura atual (thread de recepção, thread de keepalive, loop da UI) e muda nestes pontos:
- **Recepção:** só pacotes de `conn.peer`. Fluxo: `Packet::Data`, depois `transport.open`, depois `ChatPayload`.
  - `Ping`: responde `Pong`.
  - `Bye`: mostra `{peer} left the chat.`
- **Keepalive:** `Data(Ping)` a cada 15 s.
- **Perda de conexão:** se nada chegar do peer por 45 s, mostra uma vez `Connection to {peer} lost.`
- **Envio:** `Text` via `seal` e `Packet::Data`.
- **Teclado:** o loop usa `key_action`. Em `Quit`, envia `Bye` duas vezes e sai.
- Mantém as mensagens atuais de abertura (`Connected to {peer}`, `Your messages are end-to-end encrypted.`).

- [ ] **Step 4: Implementar `create`/`join`**

- **CLI:** `-p/--password` vira opcional nos dois comandos, com a doc `/// Optional extra password (both peers must use the same one)`.
- **Fluxo comum:**
  1. Valida o username.
  2. Imprime `Gathering network info...` e roda `gather()`.
  3. Se `mapped_port()` existir, imprime `UDP port {port} opened on your router (closed on exit)`.
- **create:**
  1. `SessionSecret::generate()`, depois `SessionKeys::derive` e `derive_psk(password.unwrap_or(""))`.
  2. `SessionCode { secret, direct: select_direct(&candidates) }`, impresso na caixa atual de `SESSION CODE:`.
  3. A linha `They need the same password to connect.` só aparece se houver senha.
  4. `run_session(Role::Creator, ..., vec![], closed_rx)`.
- **join:**
  1. `SessionCode::decode(code)?`.
  2. `initial_remote` = endereços diretos do código, com `infer_kind`.
  3. `run_session(Role::Joiner, ...)`.
- **run_session:**
  - `tokio::select!` entre `connect(...)` e `tokio::signal::ctrl_c()`. No Ctrl-C: fecha o portmap, imprime `Cancelled.` e encerra com `std::process::exit(130)`.
  - Sucesso: imprime `Connected to {peer} via {path}`, depois `Session fingerprint: {fp} (should match your peer's)`, e roda `P2PChat::new(...).run()`.
  - Em qualquer saída: `portmap.close().await` e depois `Session ended.`

- [ ] **Step 5: Rodar os testes e o build**

Run: `cargo test && cargo build`
Expected: todos os testes passam e o build não tem erros.

Run: `grep -rn "hole_punch\|KeyExchange\|CryptoSession\|SessionInfo\|discover_public_endpoint" src/`
Expected: nenhuma ocorrência.

- [ ] **Step 6: Verificação manual (dois terminais na mesma máquina)**

1. Terminal A: `cargo run -- create -u alice`. Copie o código.
2. Terminal B: `cargo run -- join "<código>" -u bob`.
   - Esperado: os dois mostram `Connected to ... via lan` e o mesmo fingerprint.
3. Troque mensagens nos dois sentidos. Aperte ESC em A.
   - Esperado: B mostra `alice left the chat.`
4. Repita com `-p um` em A e `-p dois` em B.
   - Esperado: B termina com `wrong password or invalid code`; A mostra `Someone tried to join with the wrong password.`

- [ ] **Step 7: Commit**

```bash
git add -A src Cargo.toml Cargo.lock
git commit -m "Wire create and join to candidate-based connection"
```

---

## Fase 3: sinalização pela DHT

### Task 11: Registros cifrados e `Signaling`

**Files:**
- Modify: `src/signal.rs`

**Interfaces:**
- Consumes:
  - `SessionKeys` (Task 5)
  - `PeerInfo`, `Role` (Task 9)
  - `public_dht` (Task 4)
- Produces:
  - `pub const SALT_CREATOR: &[u8] = b"c"; pub const SALT_JOINER: &[u8] = b"j"; pub const MAX_VALUE: usize = 1000; pub const MAX_PEER_CANDIDATES: usize = 8;`
  - `pub fn seal_info(record_key: &[u8; 32], info: &PeerInfo) -> anyhow::Result<Vec<u8>>`
    - Mantém só os 8 candidatos de maior prioridade.
    - Serializa com `serde_json` e cifra com ChaCha20-Poly1305 (`ring`); a saída é `nonce(12) || ct`.
    - Erro se passar de `MAX_VALUE`.
  - `pub fn open_info(record_key: &[u8; 32], bytes: &[u8]) -> anyhow::Result<PeerInfo>`
  - `pub struct Signaling { dht: AsyncDht, signer: mainline::SigningKey, record_key: [u8; 32] }`
  - `impl Signaling { pub fn new(keys: &SessionKeys, dht: AsyncDht) -> Self }`: `signer = SigningKey::from_bytes(&keys.dht_seed)`
  - `pub async fn publish(&self, own: Role, info: &PeerInfo) -> anyhow::Result<()>`: `MutableItem::new(signer, &sealed, info.published_ms, Some(salt))` + `put_mutable(item, None)`
  - `pub async fn fetch(&self, remote: Role) -> Option<PeerInfo>`: `get_mutable_most_recent(&pubkey, Some(salt))` + `open_info`
  - `pub fn spawn(sig: Signaling, own: Role, info: PeerInfo, poll: Duration) -> mpsc::Receiver<PeerInfo>`
    - Publica, com até 3 tentativas espaçadas de 5 s.
    - Depois consulta o salt do outro papel a cada `poll` e envia cada `PeerInfo` com `published_ms` maior que o último enviado.
    - Termina quando o receptor é descartado.

- [ ] **Step 1: Escrever os testes que falham**

```rust
fn info(n: usize) -> PeerInfo {
    let cands = (0..n).map(|i| Candidate { kind: CandidateKind::Ipv6,
        addr: format!("[2804:14c:65a1:4321:abcd:ef01:2345:{:x}]:65535", i).parse().unwrap() }).collect();
    PeerInfo { candidates: cands, published_ms: 1_700_000_000_000,
        summary: NetSummary { ipv6: true, mapped: false, cgnat: Some(true), nat: NatMapping::EndpointDependent } }
}

#[test]
fn sealed_info_roundtrips_and_needs_the_key() {
    let s = seal_info(&[1; 32], &info(3)).unwrap();
    assert_eq!(open_info(&[1; 32], &s).unwrap(), info(3));
    assert!(open_info(&[2; 32], &s).is_err());
}

#[test]
fn worst_case_fits_bep44_and_truncates_to_eight() {
    let s = seal_info(&[1; 32], &info(12)).unwrap();
    assert!(s.len() <= MAX_VALUE);
    assert_eq!(open_info(&[1; 32], &s).unwrap().candidates.len(), MAX_PEER_CANDIDATES);
}

#[tokio::test]
async fn publish_and_fetch_over_testnet() {
    let testnet = mainline::Testnet::builder(5).build().unwrap();
    let dht = || mainline::Dht::builder().bootstrap(&testnet.bootstrap)
        .bind_address(std::net::Ipv4Addr::LOCALHOST).build().unwrap().as_async();
    let keys = SessionKeys::derive(&SessionSecret([4; 16]));
    let (a, b) = (Signaling::new(&keys, dht()), Signaling::new(&keys, dht()));
    a.publish(Role::Creator, &info(2)).await.unwrap();
    assert_eq!(b.fetch(Role::Creator).await, Some(info(2)));
    assert_eq!(b.fetch(Role::Joiner).await, None);
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test signal::`
Expected: falha de compilação.

- [ ] **Step 3: Implementar**

Confira na documentação do `mainline` 8 o tipo exato de `SigningKey` (provável re-export de `ed25519_dalek`) e a API do `Testnet`. Os nomes acima seguem a documentação da versão 8.0.1.

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test signal::`
Expected: 3 testes passam.

- [ ] **Step 5: Commit**

```bash
git add src/signal.rs
git commit -m "Add encrypted peer records over Mainline DHT"
```

### Task 12: Ligar a DHT, explicar falhas e detectar código vencido

**Files:**
- Modify:
  - `src/main.rs`: criar o `Signaling` e o `spawn` em `create`/`join`
  - `src/connect.rs`: variante `Expired`
  - `src/doctor.rs`: `describe` e `explain_no_path`

**Interfaces:**
- Consumes: Tasks 9 e 11.
- Produces:
  - `ConnectError::Expired`, com `Display` `This session code has expired. Ask your peer for a new one.`
  - `doctor.rs`:
    - `pub fn describe(s: &NetSummary) -> &'static str`
    - `pub fn explain_no_path(own: &NetSummary, remote: Option<&NetSummary>) -> String`

- [ ] **Step 1: Escrever os testes que falham**

Em `doctor.rs`:

```rust
fn s(ipv6: bool, mapped: bool, cgnat: Option<bool>, nat: NatMapping) -> NetSummary { NetSummary { ipv6, mapped, cgnat, nat } }

#[test]
fn describes_networks() {
    use NatMapping::*;
    assert_eq!(describe(&s(false, false, Some(true), EndpointDependent)), "symmetric NAT behind CGNAT");
    assert_eq!(describe(&s(false, false, None, EndpointDependent)), "symmetric NAT");
    assert_eq!(describe(&s(false, false, Some(true), EndpointIndependent)), "behind CGNAT, cannot host");
    assert_eq!(describe(&s(false, false, None, Unknown)), "cannot host (no IPv6, no port mapping)");
    assert_eq!(describe(&s(false, true, None, Unknown)), "can host");
}

#[test]
fn explains_missing_and_blocked_peers() {
    use NatMapping::*;
    let own = s(false, false, Some(true), EndpointDependent);
    assert_eq!(explain_no_path(&own, None),
        "The other peer never showed up. Check that the code is complete and that they are still waiting, or run `whisper doctor`.");
    assert_eq!(explain_no_path(&own, Some(&s(false, false, None, Unknown))),
        "No direct path. You: symmetric NAT behind CGNAT. Other peer: cannot host (no IPv6, no port mapping). Try another network (Wi-Fi instead of mobile data) or run `whisper doctor`.");
}
```

Em `connect.rs`:

```rust
#[tokio::test]
async fn stale_creator_info_is_expired() {
    // quem entra recebe PeerInfo de quem cria com published_ms = agora - 12 min
    // espera: Err(Expired) em menos de 1 s
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test doctor:: connect::stale`
Expected: falha de compilação.

- [ ] **Step 3: Implementar**

- **`describe`:** testa nesta ordem:
  1. `can_host()` → `can host` (uma porta mapeada funciona mesmo com NAT simétrico).
  2. NAT simétrico com CGNAT.
  3. NAT simétrico.
  4. CGNAT.
  5. Resto.
- **`connect`:** quando o `Role::Joiner` recebe um `PeerInfo` com `agora - published_ms > creator_wait + 60 s`, retorna `Expired`.
- **`create`/`join` em `main.rs`:**
  - Monte `PeerInfo { candidates, summary, published_ms: agora }`.
  - `public_dht()`:
    - Deu certo: `spawn(Signaling::new(&keys, dht), role, info, 3 s)`.
    - Falhou: imprima `DHT unavailable; only direct connections will work.` e use um canal fechado.
  - Se o `join` estiver sem DHT e o código não tiver endereços diretos, falhe na hora com `The DHT is unreachable and this code has no direct address, so the other peer cannot be found. Check that this network allows UDP traffic.`
  - Em `ConnectError::NoPath { remote }`, imprima `explain_no_path(&gathered.summary, remote.as_ref())` em vez do `Display`.
- **Fora deste plano, de propósito:** o spec prevê republicar com `seq` maior quando os candidatos mudam. Isso exigiria detectar mudança de rede durante a espera. Cada lado publica uma vez; se a rede mudar no meio da espera de até 10 min, basta criar uma nova sessão.

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test`
Expected: todos passam.

- [ ] **Step 5: Verificação manual (duas redes)**

1. Um peer no Wi-Fi de casa e o outro no 4G (hotspot do celular), dois computadores ou um computador e uma VM com a rede do celular. Quem está no 4G cria; quem está em casa entra.
   - Esperado: conecta (porta mapeada de quem está em casa, ou hole punching) e mostra o caminho.
2. Rode `cargo run -- doctor` nas duas redes e guarde a saída para o README.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs src/connect.rs src/doctor.rs
git commit -m "Signal candidates over the DHT and explain connection failures"
```

---

## Fase 4: documentação e laboratório de NAT

### Task 13: Documentação e limpeza

**Files:**
- Modify: `README.md`, `ARCHITECTURE.md`, `CHANGELOG.md`
- Delete: `P2P_TROUBLESHOOTING.md`, `RELAYS.md`, `DEPLOY.md`

- [ ] **Step 1: Atualizar o README**

- Uso com senha opcional.
- `whisper doctor`, com uma saída de exemplo real (com IPs mascarados).
- "How it works" com a escada IPv6 → porta no roteador → hole punching pela DHT → falha explicada.
- "What third parties see": servidores STUN veem seu IP; nós da DHT veem um bloco cifrado e o IP de quem consulta; ninguém vê mensagens.
- Nota do firewall do Windows: na primeira execução, permitir também redes públicas; sem isso, a conexão pode levar até ~20 s.
- Limitações: NAT simétrico dos dois lados não conecta.

- [ ] **Step 2: Atualizar o ARCHITECTURE.md**

- O princípio vira "zero custo de infraestrutura" (STUN e DHT públicos permitidos; relay proibido).
- Substitua as seções de hole punching de um lado só e o formato de código antigo pelo desenho atual, com link para o spec.

- [ ] **Step 3: CHANGELOG**

Seção `## [Unreleased]` com: código v3 (incompatível com 0.2), conexão por candidatos, abertura de porta, DHT, Noise com senha opcional, `whisper doctor`, limite de mensagem de 1000 bytes.

- [ ] **Step 4: Apagar os docs obsoletos e verificar**

Run: `git rm P2P_TROUBLESHOOTING.md RELAYS.md DEPLOY.md && grep -rn "t-chat\|relay server" README.md ARCHITECTURE.md`
Expected: nenhuma ocorrência.

- [ ] **Step 5: Commit**

```bash
git add -A README.md ARCHITECTURE.md CHANGELOG.md
git commit -m "Document zero-infra connection model and remove relay docs"
```

### Task 14: Ganchos de teste e peças do laboratório

**Files:**
- Modify: `src/stun.rs`, `src/signal.rs`, `src/main.rs`
- Create: `examples/stun_responder.rs`, `examples/dht_bootstrap.rs`

**Interfaces:**
- Produces, todos lidos só de variáveis de ambiente, sem flag na CLI:
  - `WHISPER_STUN_SERVERS`: lista `host:porta` separada por vírgula. Substitui `STUN_SERVERS`; `probe_nat` usa os dois primeiros da lista.
  - `WHISPER_DHT_BOOTSTRAP`: lista separada por vírgula. `public_dht()` passa a usar `Dht::builder().bootstrap(..)`.
  - `WHISPER_TEST_EXIT_ON_CONNECT=1`: após conectar, imprime `CONNECTED via {path}` em stdout e sai com código 0, sem abrir o chat. Em falha, sai com código 1.
  - `WHISPER_TEST_CODE_FILE=<caminho>`: quem cria grava o código nesse arquivo.
  - `cargo run --example stun_responder -- <ip:porta>`: responde Binding Requests com XOR-MAPPED-ADDRESS do remetente.
  - `cargo run --example dht_bootstrap -- <ip> <n>`: sobe `n` nós Mainline em modo servidor nesse IP, imprime a lista de bootstrap numa linha (separada por vírgula) e roda até ser morto.

- [ ] **Step 1: Escrever o teste que falha (em `stun.rs`)**

```rust
#[tokio::test]
async fn env_override_points_probe_at_local_responder() {
    // sobe um responder STUN mínimo em 127.0.0.1:0 dentro do teste;
    // com WHISPER_STUN_SERVERS="127.0.0.1:<p>,127.0.0.1:<p>", probe_nat retorna
    // Some(endereço local do socket) e NatMapping::EndpointIndependent
}
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `cargo test stun::env_override`
Expected: FAIL (a variável ainda é ignorada).

- [ ] **Step 3: Implementar os ganchos e os dois exemplos**

O responder do teste e o de `examples/stun_responder.rs` podem compartilhar a lógica de resposta se ela ficar em `stun.rs` como `pub fn build_binding_response(txid: &[u8; 12], addr: SocketAddrV4) -> Vec<u8>`. É a mesma função que o helper `response_for` da Task 1 precisa; substitua o helper por ela.

- [ ] **Step 4: Rodar e ver passar**

Run: `cargo test && cargo build --examples`
Expected: todos passam e os exemplos compilam.

- [ ] **Step 5: Commit**

```bash
git add src/stun.rs src/signal.rs src/main.rs examples/
git commit -m "Add test hooks and NAT lab helpers"
```

### Task 15: Laboratório de NAT e CI

**Files:**
- Create: `scripts/natlab.sh`, `.github/workflows/ci.yml`

**Topologia (Linux, root, `ip netns` + `iptables`):**
- Namespace `inet` com 203.0.113.1, onde rodam `stun_responder` (porta 3478, e uma segunda instância em 203.0.113.2:3478, para o teste de NAT simétrico ter dois IPs) e `dht_bootstrap` (5 nós).
- Roteadores `ra` (WAN 203.0.113.10, LAN 10.0.1.1/24) e `rb` (WAN 203.0.113.20, LAN 10.0.2.1/24), com `MASQUERADE` na WAN.
- Hosts `a1`, `a2` atrás de `ra` e `b1` atrás de `rb`.
- O NAT simétrico é o mesmo roteador com `MASQUERADE --random-fully`.
- Os peers rodam com `WHISPER_STUN_SERVERS`, `WHISPER_DHT_BOOTSTRAP`, `WHISPER_TEST_EXIT_ON_CONNECT=1` e `WHISPER_TEST_CODE_FILE`, e timeouts padrão.

**Cenários e resultado esperado (o script falha se algum divergir):**

| Cenário | Quem cria | Quem entra | Esperado |
|---|---|---|---|
| cone ↔ cone | a1 (ra normal) | b1 (rb normal) | `CONNECTED via` (reflexive ou peer-reflexive), código 0 |
| mesma LAN | a1 | a2 | `CONNECTED via lan`, código 0 |
| simétrico ↔ cone | a1 (ra `--random-fully`) | b1 (rb normal) | código 1 com `No direct path`, em até 70 s |
| simétrico ↔ simétrico | a1 (ra `--random-fully`) | b1 (rb `--random-fully`) | código 1 com `symmetric NAT`, em até 70 s |

- [ ] **Step 1: Escrever `scripts/natlab.sh`**

- Monta a topologia, roda cada cenário com `timeout 90` e compara o resultado com a tabela.
- Imprime `PASS <cenário>` ou `FAIL <cenário>: <saída>`.
- Desmonta tudo num `trap` de saída.
- Sai com código diferente de 0 se algum cenário falhar.

- [ ] **Step 2: Rodar localmente (Linux ou VM)**

Run: `cargo build --release --examples && sudo scripts/natlab.sh`
Expected: 4 linhas `PASS` e código de saída 0.

- [ ] **Step 3: Escrever `.github/workflows/ci.yml`**

- Em `push` e `pull_request`.
- Job `test`: matriz ubuntu, macos e windows rodando `cargo test`. Os testes `#[ignore]` ficam de fora.
- Job `natlab`: ubuntu-latest, `cargo build --release --examples` e depois `sudo scripts/natlab.sh`.

- [ ] **Step 4: Verificar no GitHub**

Run: `git push -u origin p2p-sem-infra`, depois `gh run watch`
Expected: os jobs `test` e `natlab` verdes. Antes do push, confirme com o usuário.

- [ ] **Step 5: Commit**

```bash
git add scripts/natlab.sh .github/workflows/ci.yml
git commit -m "Add NAT simulation lab and CI workflow"
```
