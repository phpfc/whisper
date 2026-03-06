# Guia de Deploy do t-chat

## Opção 1: VPS/Servidor Cloud (Recomendado)

### Passo 1: Configure um servidor (AWS, DigitalOcean, etc)

```bash
# No servidor
git clone <seu-repo>
cd t-chat
cargo build --release

# Inicie o servidor
./target/release/t-chat server --addr 0.0.0.0:8080
```

### Passo 2: Configure o firewall

```bash
# Abra a porta 8080
sudo ufw allow 8080/tcp
```

### Passo 3: Clientes se conectam

```bash
# De qualquer lugar do mundo
./t-chat create --username Alice --password senha --server SEU_IP:8080
./t-chat join --session ID --username Bob --password senha --server SEU_IP:8080
```

## Opção 2: Túnel com ngrok (Teste rápido)

```bash
# Terminal 1: Inicie o servidor local
./target/release/t-chat server

# Terminal 2: Crie túnel ngrok
ngrok tcp 8080

# Use o endereço ngrok (ex: 0.tcp.ngrok.io:12345)
./t-chat create --username Alice --password senha --server 0.tcp.ngrok.io:12345
```

## Opção 3: Docker (Facilitado)

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
# Build e run
docker build -t t-chat .
docker run -p 8080:8080 t-chat
```

## Considerações de Segurança

### ✅ O que está protegido:
- **Conteúdo das mensagens**: Criptografado E2E com ChaCha20-Poly1305
- **Troca de chaves**: X25519 Diffie-Hellman
- **Autenticação**: Hash SHA-256 da senha

### ⚠️ Limitações atuais:
- **Sem TLS/SSL**: Tráfego de controle não está criptografado em trânsito
- **Sem perfect forward secrecy**: As chaves não são rotacionadas
- **Servidor vê metadados**: IP, horários de conexão, tamanho das mensagens
- **Sem verificação de identidade**: Não há fingerprints ou verificação de chaves

## Melhorias Recomendadas para Produção

1. **Adicionar TLS**
   - Use certificados Let's Encrypt
   - Implemente conexões TLS entre cliente-servidor

2. **Melhorar a criptografia**
   - Implementar forward secrecy (rotação de chaves)
   - Adicionar autenticação de mensagens

3. **Adicionar rate limiting**
   - Prevenir spam e DoS

4. **Logs e monitoramento**
   - Manter logs (sem conteúdo de mensagens)
   - Alertas de segurança

5. **Persistência opcional**
   - Sessões sobreviverem a restart do servidor
   - Histórico criptografado local

## Exemplo de Deploy Completo

```bash
# 1. Servidor em VPS
ssh user@seu-servidor.com
git clone https://github.com/seu-usuario/t-chat
cd t-chat
cargo build --release

# 2. Crie serviço systemd
sudo nano /etc/systemd/system/t-chat.service
```

```ini
[Unit]
Description=t-chat Server
After=network.target

[Service]
Type=simple
User=tchat
WorkingDirectory=/home/tchat/t-chat
ExecStart=/home/tchat/t-chat/target/release/t-chat server --addr 0.0.0.0:8080
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# 3. Inicie o serviço
sudo systemctl enable t-chat
sudo systemctl start t-chat
sudo systemctl status t-chat
```

## URLs de Exemplo

### Servidor Local (desenvolvimento)
```
127.0.0.1:8080
```

### Servidor em VPS
```
123.45.67.89:8080
seu-dominio.com:8080
```

### Com ngrok (testes)
```
0.tcp.ngrok.io:12345
```

## Custos Estimados

- **VPS básico**: $5-10/mês (DigitalOcean, Vultr, Linode)
- **AWS Lightsail**: $3.50-5/mês
- **ngrok grátis**: Limitado, mas suficiente para testes
- **Servidor próprio**: Apenas eletricidade + internet

## Suporte

Para deploy em produção, considere:
- Backup regular
- Monitoramento de uptime
- Plano de disaster recovery
- Documentação de incidentes
