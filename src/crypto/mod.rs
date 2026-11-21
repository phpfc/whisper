use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Parâmetros do handshake Noise: sem chaves estáticas, a autenticação vem da PSK.
pub const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

/// Tamanho da tag de autenticação do ChaChaPoly.
const TAG_LEN: usize = 16;

/// Inicia o lado de quem entra na sessão, o joiner (envia a msg1).
pub fn initiator(psk: &[u8; 32]) -> Result<snow::HandshakeState> {
    Ok(snow::Builder::new(NOISE_PARAMS.parse()?)
        .psk(0, psk)?
        .build_initiator()?)
}

/// Inicia o lado de quem cria a sessão, o creator (responde a msg1 com a msg2).
pub fn responder(psk: &[u8; 32]) -> Result<snow::HandshakeState> {
    Ok(snow::Builder::new(NOISE_PARAMS.parse()?)
        .psk(0, psk)?
        .build_responder()?)
}

/// Janela anti-replay de 64 pacotes, como no WireGuard.
/// O bit `i` de `bitmap` marca que o nonce `highest - i` já foi visto.
#[derive(Default)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registra o nonce e devolve `true` se ele é novo e ainda está na janela.
    /// Só deve ser chamado para nonces de pacotes já autenticados.
    pub fn accept(&mut self, nonce: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(nonce);
            self.bitmap = 1;
            return true;
        };

        if nonce > highest {
            let shift = nonce - highest;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = Some(nonce);
            return true;
        }

        let behind = highest - nonce;
        if behind >= 64 || self.bitmap & (1 << behind) != 0 {
            return false;
        }
        self.bitmap |= 1 << behind;
        true
    }
}

/// Transporte cifrado sobre pacotes UDP, que podem chegar fora de ordem ou repetidos.
/// Cada pacote leva o nonce explícito; é seguro compartilhar entre threads (`Arc`).
pub struct Transport {
    state: snow::StatelessTransportState,
    send_nonce: AtomicU64,
    replay: Mutex<ReplayWindow>,
}

impl Transport {
    /// Converte um handshake concluído em transporte e devolve o fingerprint da sessão.
    pub fn from_handshake(hs: snow::HandshakeState) -> Result<(Self, String)> {
        // O hash precisa ser lido antes de consumir o handshake.
        let fingerprint = session_fingerprint(hs.get_handshake_hash());
        let state = hs.into_stateless_transport_mode()?;
        let transport = Self {
            state,
            send_nonce: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::new()),
        };
        Ok((transport, fingerprint))
    }

    /// Cifra `plaintext` e devolve o nonce usado junto com o texto cifrado.
    pub fn seal(&self, plaintext: &[u8]) -> Result<(u64, Vec<u8>)> {
        // u64::MAX é reservado pelo Noise e o snow o recusa; chegar a 2^64
        // pacotes é inalcançável na prática.
        let nonce = self.send_nonce.fetch_add(1, Ordering::Relaxed);

        let mut out = vec![0u8; plaintext.len() + TAG_LEN];
        let len = self.state.write_message(nonce, plaintext, &mut out)?;
        out.truncate(len);
        Ok((nonce, out))
    }

    /// Decifra um pacote e rejeita replay ou nonce velho demais.
    /// O nonce só entra na janela depois que a autenticação passa, para que
    /// um pacote forjado não consuma um nonce legítimo.
    pub fn open(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; ciphertext.len()];
        let len = self
            .state
            .read_message(nonce, ciphertext, &mut out)
            .map_err(|_| anyhow!("Decryption failed"))?;
        out.truncate(len);

        let fresh = self
            .replay
            .lock()
            .map_err(|_| anyhow!("Replay window unavailable"))?
            .accept(nonce);
        if !fresh {
            return Err(anyhow!("Replayed or stale packet"));
        }
        Ok(out)
    }
}

/// Fingerprint da sessão a partir do hash do handshake: os 16 primeiros bytes
/// em hex maiúsculo, em 4 grupos de 8.
pub fn session_fingerprint(hash: &[u8]) -> String {
    hash[..hash.len().min(16)]
        .chunks(4)
        .map(|group| group.iter().map(|b| format!("{:02X}", b)).collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Roda o handshake em memória; payload da msg1 = "bob", da msg2 = "alice".
    fn handshake(
        psk_i: [u8; 32],
        psk_r: [u8; 32],
    ) -> Result<((Transport, String), (Transport, String))> {
        let mut init = initiator(&psk_i)?;
        let mut resp = responder(&psk_r)?;
        let mut msg = [0u8; 1024];
        let mut out = [0u8; 1024];

        let n = init.write_message(b"bob", &mut msg)?;
        let m = resp.read_message(&msg[..n], &mut out)?;
        assert_eq!(&out[..m], b"bob");

        let n = resp.write_message(b"alice", &mut msg)?;
        let m = init.read_message(&msg[..n], &mut out)?;
        assert_eq!(&out[..m], b"alice");

        Ok((Transport::from_handshake(init)?, Transport::from_handshake(resp)?))
    }

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

    #[test]
    fn replay_window_edges() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(64));
        assert!(!w.accept(0)); // 64 atrás: já fora da janela
        assert!(w.accept(1)); // 63 atrás: ainda dentro
        assert!(!w.accept(1));
        assert!(w.accept(u64::MAX));
        assert!(!w.accept(u64::MAX));
        assert!(!w.accept(64));
    }

    #[test]
    fn replay_window_remembers_seen_nonces_after_advancing() {
        // avanço pequeno: o 5 já visto continua marcado
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(w.accept(6));
        assert!(!w.accept(5));
        assert!(!w.accept(6));

        // avanço de 63: o bit mais antigo ainda cabe na janela
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(63));
        assert!(!w.accept(0));
        assert!(!w.accept(63));

        // vários avanços seguidos mantêm o histórico
        let mut w = ReplayWindow::new();
        for n in [3, 4, 7, 20, 21] {
            assert!(w.accept(n));
        }
        for n in [3, 4, 7, 20, 21] {
            assert!(!w.accept(n), "nonce {n} should be remembered");
        }
        assert!(w.accept(5)); // nunca visto, ainda dentro da janela
    }

    #[test]
    fn replay_of_older_packet_after_newer_one_is_rejected() {
        let ((ti, _), (tr, _)) = handshake([1; 32], [1; 32]).unwrap();
        let (n5, ct5) = ti.seal(b"cinco").unwrap();
        let (n6, ct6) = ti.seal(b"seis").unwrap();
        assert!(tr.open(n5, &ct5).is_ok());
        assert!(tr.open(n6, &ct6).is_ok());
        // o nonce mais antigo já foi aceito antes de a janela avançar
        assert!(tr.open(n5, &ct5).is_err());
        assert!(tr.open(n6, &ct6).is_err());
    }

    #[test]
    fn forged_packet_does_not_burn_the_nonce() {
        let ((ti, _), (tr, _)) = handshake([1; 32], [1; 32]).unwrap();
        let (n, ct) = ti.seal(b"legit").unwrap();
        let mut forged = ct.clone();
        forged[0] ^= 0x01;
        assert!(tr.open(n, &forged).is_err());
        assert_eq!(tr.open(n, &ct).unwrap(), b"legit");
    }

    #[test]
    fn truncated_or_empty_ciphertext_is_rejected() {
        let ((ti, _), (tr, _)) = handshake([1; 32], [1; 32]).unwrap();
        let (n, ct) = ti.seal(b"legit").unwrap();
        assert!(tr.open(n, &[]).is_err());
        assert!(tr.open(n, &ct[..ct.len() - 1]).is_err());
        assert!(tr.open(n, &ct).is_ok());
    }

    #[test]
    fn seal_uses_increasing_nonces_and_adds_tag() {
        let ((ti, _), _) = handshake([1; 32], [1; 32]).unwrap();
        let (n0, ct0) = ti.seal(b"abc").unwrap();
        let (n1, _) = ti.seal(b"abc").unwrap();
        assert_eq!(n1, n0 + 1);
        assert_eq!(ct0.len(), 3 + 16);
    }

    #[test]
    fn out_of_order_delivery_is_accepted_but_stale_is_not() {
        let ((ti, _), (tr, _)) = handshake([1; 32], [1; 32]).unwrap();
        let sealed: Vec<_> = (0..70u8).map(|i| ti.seal(&[i]).unwrap()).collect();
        // chega fora de ordem
        assert!(tr.open(sealed[2].0, &sealed[2].1).is_ok());
        assert!(tr.open(sealed[0].0, &sealed[0].1).is_ok());
        assert!(tr.open(sealed[1].0, &sealed[1].1).is_ok());
        // o último avança a janela e o nonce 3 fica 66 atrás
        assert!(tr.open(sealed[69].0, &sealed[69].1).is_ok());
        assert!(tr.open(sealed[3].0, &sealed[3].1).is_err());
        assert!(tr.open(sealed[68].0, &sealed[68].1).is_ok());
    }

    #[test]
    fn own_packets_do_not_open_on_the_same_side() {
        let ((ti, _), (tr, _)) = handshake([1; 32], [1; 32]).unwrap();
        let (n, ct) = ti.seal(b"x").unwrap();
        assert!(ti.open(n, &ct).is_err()); // reflexão
        assert!(tr.open(n, &ct).is_ok());
    }

    #[test]
    fn sessions_have_distinct_fingerprints() {
        let ((_, f1), _) = handshake([1; 32], [1; 32]).unwrap();
        let ((_, f2), _) = handshake([1; 32], [1; 32]).unwrap();
        assert_ne!(f1, f2);
    }

    #[test]
    fn session_fingerprint_format() {
        let hash: Vec<u8> = (0u8..32).collect();
        assert_eq!(session_fingerprint(&hash), "00010203 04050607 08090A0B 0C0D0E0F");
        assert_eq!(session_fingerprint(&[0xAB; 32]).len(), 35);
        // hash curto não deve causar pânico
        assert_eq!(session_fingerprint(&[1, 2, 3]), "010203");
        assert_eq!(session_fingerprint(&[]), "");
    }

    #[test]
    fn transport_is_shareable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Transport>();
    }
}
