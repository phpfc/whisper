# Lista de Relays Públicos do t-chat

Este arquivo mantém uma lista de servidores relay públicos disponíveis para uso com t-chat.

## Relays Ativos

### Relays Oficiais
Nenhum no momento. A comunidade está convidada a hospedar!

### Relays da Comunidade
Adicione seu relay aqui via Pull Request!

```
# Formato:
# hostname:porta | Mantenedor | Localização | Uptime estimado
# exemplo.com:8080 | @seu-github | Brasil | 99%
```

## Como Hospedar um Relay

### Opção 1: Servidor Próprio (VPS)

```bash
# 1. Instale t-chat
git clone https://github.com/seu-usuario/t-chat
cd t-chat
cargo build --release

# 2. Rode o servidor
./target/release/t-chat server --addr 0.0.0.0:8080

# 3. Configure firewall para abrir porta 8080
sudo ufw allow 8080/tcp
```

### Opção 2: Fly.io (Gratuito)

```bash
# 1. Instale Fly CLI
curl -L https://fly.io/install.sh | sh

# 2. Crie conta e login
fly auth signup

# 3. Crie fly.toml no diretório do projeto:
```

```toml
# fly.toml
app = "tchat-relay-seunome"

[build]
  dockerfile = "Dockerfile"

[[services]]
  internal_port = 8080
  protocol = "tcp"

  [[services.ports]]
    port = 8080
```

```dockerfile
# Dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/t-chat /usr/local/bin/
EXPOSE 8080
CMD ["t-chat", "server", "--addr", "0.0.0.0:8080"]
```

```bash
# 4. Deploy
fly launch
fly deploy
```

### Opção 3: Railway.app (Gratuito)

1. Faça fork do repositório t-chat
2. Conecte ao Railway.app
3. Configure:
   - Build Command: `cargo build --release`
   - Start Command: `./target/release/t-chat server --addr 0.0.0.0:${PORT}`
4. Deploy!

### Opção 4: Render.com (Gratuito)

1. Fork do repositório
2. Crie "New Web Service" no Render
3. Configure:
   - Build Command: `cargo build --release`
   - Start Command: `./target/release/t-chat server --addr 0.0.0.0:10000`
4. Deploy!

## Como Adicionar Seu Relay à Lista

1. Fork este repositório
2. Edite `src/relay.rs` e adicione seu servidor em `KNOWN_PUBLIC_RELAYS`:

```rust
const KNOWN_PUBLIC_RELAYS: &[&str] = &[
    "seu-relay.fly.dev:8080",  // Adicione aqui
    "127.0.0.1:8080",
];
```

3. Edite este arquivo (RELAYS.md) e adicione na seção "Relays da Comunidade"
4. Envie Pull Request!

## Requisitos para Relays Públicos

- ✅ Uptime mínimo de 90%
- ✅ Latência baixa (< 200ms)
- ✅ Sem logs de conteúdo (apenas conexões)
- ✅ HTTPS/TLS opcional (recomendado)
- ✅ IPv6 opcional

## Monitoramento

Status dos relays: (TODO: adicionar página de status)

## Custos

### Opções Gratuitas:
- **Fly.io**: 3 VMs gratuitas, suficiente para relay leve
- **Railway**: $5 crédito/mês, geralmente sobra
- **Render**: 750h gratuitas/mês

### Custo Estimado (VPS):
- Relay leve: $5/mês (DigitalOcean Droplet básico)
- Tráfego: ~1GB/dia para 100 usuários ativos

## Perguntas Frequentes

### O relay pode ler minhas mensagens?
**Não!** O relay apenas retransmite pacotes criptografados. A criptografia E2E acontece nos clientes, o relay nunca vê o texto plano.

### Quantos usuários um relay suporta?
Depende do servidor. Um Fly.io gratuito suporta ~50-100 usuários simultâneos.

### Posso rodar temporariamente?
Sim! Rode `./t-chat server` quando quiser usar, desligue depois. Apenas certifique-se que seus amigos saibam quando está online.

### E se o relay cair?
O t-chat tentará outros relays da lista automaticamente. As sessões em andamento serão desconectadas, mas podem reconectar em outro relay.

## Contribuindo

PRs são bem-vindos para:
- Adicionar novos relays públicos
- Melhorar descoberta automática de relays
- Adicionar monitoramento de saúde
- Implementar DHT/descoberta P2P de relays

## Licença

Relays públicos devem seguir a mesma licença MIT do projeto.
