# Análise de Segurança do t-chat

## Status Atual: ⚠️ USO CASUAL APENAS

Este documento detalha as vulnerabilidades conhecidas e melhorias necessárias para tornar o t-chat seguro contra adversários ativos.

---

## ✅ Pontos Fortes

### Criptografia End-to-End
- **Algoritmo**: ChaCha20-Poly1305 (moderno e seguro)
- **Troca de Chaves**: X25519 Diffie-Hellman
- **Relay cego**: Servidor não consegue descriptografar mensagens
- **Localização**: `src/crypto/mod.rs`

### Mensagens Efêmeras
- Nenhuma mensagem é armazenada em disco
- Relay apenas retransmite, não persiste dados
- Sessões existem apenas em memória

### Proteção de Sessão
- Sessões protegidas por senha
- Hash SHA-256 (mas veja vulnerabilidades abaixo)

---

## 🔴 VULNERABILIDADES CRÍTICAS

### 1. Hash de Senha Sem Salt (CRÍTICO)
**Localização**: `src/session/mod.rs:75-78`

**Código vulnerável**:
```rust
pub fn new(password: &str) -> Self {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let password_hash: [u8; 32] = hasher.finalize().into();
    Self { password_hash }
}
```

**Problema**:
- Senhas idênticas geram o mesmo hash
- Vulnerável a rainbow tables
- Vulnerável a ataques de dicionário
- Sem salt = atacante pode pré-computar hashes

**Impacto**: Senhas fracas podem ser quebradas offline

**Solução**:
- Usar Argon2id, bcrypt ou scrypt
- Adicionar salt único por sessão
- Exemplo: `argon2 = "0.5"`

```rust
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString, rand_core::OsRng};

pub fn new(password: &str) -> Self {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    // ...
}
```

---

### 2. Sem Autenticação do Relay (CRÍTICO)
**Localização**: `src/p2p/mod.rs:114-164`

**Problema**:
- Relay aceita qualquer mensagem `Join` sem verificação
- Atacante pode enviar `JoinAck` falso
- Pode injetar chaves públicas maliciosas durante troca
- Man-in-the-Middle possível durante key exchange

**Cenário de ataque**:
1. Alice e Bob conectam ao relay
2. Atacante intercepta troca de chaves
3. Atacante envia sua própria chave pública para ambos
4. Alice e Bob pensam que estão falando entre si, mas estão falando com o atacante

**Impacto**: MITM completo, E2E é inútil

**Soluções**:
- **Opção A**: TLS/SSL no relay (protege canal)
- **Opção B**: Assinar mensagens de key exchange com chave derivada da senha
- **Opção C**: Verificação manual de fingerprints (como Signal/WhatsApp)

---

### 3. Pass-the-Hash (CRÍTICO)
**Localização**: `src/session/mod.rs:121`

**Problema**:
```rust
SessionMessage::Join {
    session_id: SessionId,
    password_hash: [u8; 32],  // Hash transmitido na rede!
    ...
}
```

O hash da senha é enviado na rede. Atacante que capturar o hash pode:
- Reusar o hash para entrar na sessão (pass-the-hash)
- Não precisa quebrar a senha

**Impacto**: Captura de tráfego = acesso à sessão

**Solução**:
- Challenge-response (relay envia desafio, cliente prova que conhece a senha)
- Ou TLS para proteger a transmissão

---

### 4. Nonce Pode Repetir (ALTO)
**Localização**: `src/crypto/mod.rs:25-29`

**Código**:
```rust
let mut nonce_bytes = [0u8; 12];
self.rng.fill(&mut nonce_bytes)?;
let nonce = Nonce::assume_unique_for_key(nonce_bytes);
```

**Problema**:
- Depende 100% de `SystemRandom` ter boa entropia
- Se RNG falhar ou tiver baixa entropia, nonces podem repetir
- **Nonce repetido com mesma chave = quebra total de ChaCha20-Poly1305**
- `assume_unique_for_key` não verifica, apenas assume

**Impacto**: Repetição de nonce expõe keystream e permite descriptografar mensagens

**Solução**:
- Usar contador + random (híbrido)
- Verificar unicidade
- Ou usar nonce de 192 bits para garantir unicidade estatística

```rust
// Melhor abordagem:
struct CryptoSession {
    shared_secret: [u8; 32],
    counter: AtomicU64,  // garante unicidade
    rng: SystemRandom,
}

// Nonce = counter (8 bytes) + random (4 bytes)
```

---

### 5. Sem Perfect Forward Secrecy (MÉDIO)
**Localização**: `src/crypto/mod.rs:65-86`

**Problema**:
- `EphemeralSecret` é gerado uma vez por sessão
- Se o segredo vazar (dump de memória, bug), **todas as mensagens da sessão** são comprometidas
- Não há renegociação de chaves

**Impacto**: Comprometimento retroativo de todas as mensagens

**Solução**:
- Implementar Double Ratchet (como Signal)
- Renegociar chaves a cada N mensagens ou T minutos

---

### 6. Sem Verificação de Identidade (ALTO)
**Problema atual**:
- Bob não tem como verificar que está falando com Alice de verdade
- Não há fingerprints ou safety numbers
- Usuário não pode detectar MITM

**Cenário**:
- Alice compartilha session code
- Atacante intercepta e modifica
- Bob conecta ao atacante achando que é Alice

**Impacto**: Usuários não conseguem detectar MITM

**Solução**:
- Mostrar fingerprint das chaves públicas (SHA-256 dos primeiros bytes)
- Usuários comparam por canal alternativo (telefone, presencial)
- Exemplo:
```
Alice's fingerprint: 4A3B 9C2D 1E5F 8A7B
Bob's fingerprint:   7F2E 4D9A 3C1B 6E8A

Compare estes códigos por telefone ou pessoalmente.
```

---

### 7. Sem Rate Limiting (MÉDIO)
**Localização**: `src/p2p/mod.rs:102-110`

**Problema**:
```rust
loop {
    let (stream, _) = listener.accept().await?;
    tokio::spawn(async move { ... });
}
```

- Aceita conexões ilimitadas
- Sem limite de tentativas de senha
- Sem proteção contra DoS

**Ataques possíveis**:
- Brute force de senhas
- DoS por exaustão de recursos
- Spam de sessões

**Solução**:
- Rate limiting por IP (ex: 5 tentativas/minuto)
- Limite de conexões simultâneas
- Backoff exponencial para tentativas falhadas

---

### 8. Timing Attack na Comparação de Hash (BAIXO)
**Localização**: `src/session/mod.rs:87` e `src/p2p/mod.rs:162`

**Código**:
```rust
self.password_hash == test_hash  // Comparação normal
existing_session.password_hash != password_hash
```

**Problema**:
- Comparação `==` não é constant-time
- Atacante pode medir tempo de resposta para adivinhar bytes do hash

**Impacto**: Facilita brute force (baixo impacto devido a outras vulnerabilidades maiores)

**Solução**:
```rust
use subtle::ConstantTimeEq;
self.password_hash.ct_eq(&test_hash).into()
```

---

### 9. UUID v4 Previsível (BAIXO)
**Localização**: `src/session/mod.rs:10`

**Código**:
```rust
pub fn new() -> Self {
    Self(Uuid::new_v4().to_string())
}
```

**Problema**:
- Session IDs podem ser adivinhados se RNG for fraco
- Permite ataques de enumeração de sessões

**Impacto**: Atacante pode tentar adivinhar IDs de sessões ativas

**Solução**:
- Usar 256 bits de entropia criptográfica
- Ou adicionar HMAC do session ID com chave secreta do relay

---

### 10. UPnP Expõe Máquina (MÉDIO)
**Localização**: `src/upnp.rs:16-26`

**Problema**:
- Abre porta 8080 automaticamente no roteador
- Expõe a máquina do usuário à internet
- Relay não tem proteção contra ataques

**Impacto**:
- Máquina fica acessível pela internet
- Se relay tiver vulnerabilidade, atacante pode explorar

**Solução**:
- Adicionar firewall no relay (apenas conexões de chat)
- Rate limiting obrigatório
- Avisar usuário que porta será aberta

---

## 📊 Resumo de Risco

| Vulnerabilidade | Severidade | Facilidade de Exploração | Prioridade |
|----------------|------------|--------------------------|------------|
| Hash sem salt | 🔴 Alta | Média | P0 |
| Sem autenticação relay | 🔴 Alta | Alta | P0 |
| Pass-the-hash | 🔴 Alta | Alta | P0 |
| Nonce pode repetir | 🟠 Média | Baixa | P1 |
| Sem verificação identidade | 🟠 Média | Alta | P1 |
| Sem forward secrecy | 🟡 Baixa | Baixa | P2 |
| Sem rate limiting | 🟠 Média | Alta | P1 |
| Timing attack | 🟢 Muito Baixa | Média | P3 |
| UUID previsível | 🟢 Muito Baixa | Baixa | P3 |
| UPnP expõe máquina | 🟠 Média | Média | P1 |

---

## 🎯 Recomendações Imediatas (P0)

Para tornar o app seguro para uso real, implementar:

### 1. Argon2 para Senhas
```toml
[dependencies]
argon2 = "0.5"
```

### 2. TLS no Relay
```toml
[dependencies]
tokio-rustls = "0.25"
rustls-pemfile = "2.0"
```

### 3. Fingerprint Verification
Mostrar na tela:
```
🔐 Security Code: 4A3B 9C2D 1E5F
Compare com seu contato por outro canal!
```

### 4. Rate Limiting Básico
```rust
use std::collections::HashMap;
use std::time::{Instant, Duration};

// Limitar 5 tentativas por IP a cada 60 segundos
```

---

## 🛡️ Modelo de Ameaça

### Contra o que PROTEGE:
- ✅ Relay malicioso lendo mensagens (E2E funciona)
- ✅ Intercepção passiva de tráfego (mensagens criptografadas)
- ✅ Replay de mensagens antigas (timestamps implícitos)

### Contra o que NÃO PROTEGE:
- ❌ Man-in-the-Middle ativo durante conexão inicial
- ❌ Brute force de senhas fracas
- ❌ Relay injetando chaves públicas falsas
- ❌ Comprometimento retroativo (se chave vazar)
- ❌ DoS attacks no relay

---

## 📝 Comparação com Apps Conhecidos

| Feature | t-chat | Signal | WhatsApp | Telegram |
|---------|--------|--------|----------|----------|
| E2E Encryption | ✅ | ✅ | ✅ | ❌ (apenas secret chats) |
| Forward Secrecy | ❌ | ✅ | ✅ | ✅ |
| Fingerprint Verification | ❌ | ✅ | ✅ | ✅ |
| TLS/Transport Security | ❌ | ✅ | ✅ | ✅ |
| Password KDF | ❌ | ✅ | ✅ | ✅ |
| Rate Limiting | ❌ | ✅ | ✅ | ✅ |

**Conclusão**: t-chat tem crypto básico correto, mas falta proteção em várias camadas.

---

## 🚀 Roadmap de Segurança

### Fase 1: Tornar Usável com Segurança Básica (P0)
- [ ] Implementar Argon2id para hash de senha
- [ ] Adicionar TLS no relay (Let's Encrypt)
- [ ] Mostrar fingerprints para verificação manual
- [ ] Rate limiting básico (por IP)

### Fase 2: Forward Secrecy (P1)
- [ ] Implementar Double Ratchet (Signal Protocol)
- [ ] Renegociar chaves a cada 100 mensagens
- [ ] Deletar chaves antigas da memória

### Fase 3: Proteção Contra DoS (P1)
- [ ] Rate limiting avançado
- [ ] Limite de conexões simultâneas por IP
- [ ] Captcha ou proof-of-work para criar sessões

### Fase 4: Auditoria e Hardening (P2)
- [ ] Auditoria de segurança profissional
- [ ] Fuzzing do parser de mensagens
- [ ] Memory safety audit
- [ ] Adicionar canary tokens para detectar vazamentos

---

## 🎓 Para Desenvolvedores

### Antes de usar em produção:
1. ⚠️ **NÃO use para comunicação sensível** (segredos corporativos, dados pessoais)
2. ✅ **OK para uso casual** entre amigos (melhor que SMS)
3. 🔒 **Implemente P0 primeiro** se quiser usar com adversários

### Reportando Vulnerabilidades:
Se encontrar vulnerabilidades não listadas aqui, por favor reporte via:
- GitHub Issues (para bugs públicos)
- Email privado (para vulnerabilidades sérias)

---

## 📚 Referências

- [Signal Protocol](https://signal.org/docs/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [ChaCha20-Poly1305 Spec](https://tools.ietf.org/html/rfc8439)
- [X25519 Spec](https://tools.ietf.org/html/rfc7748)
- [Password Hashing Competition](https://www.password-hashing.net/)

---

**Última atualização**: 2026-03-06
**Versão analisada**: v0.1.0
