# t-chat

Uma ferramenta CLI de chat simples, segura e privada construída em Rust.

## Características

- **🔐 Criptografia End-to-End**: Todas as mensagens são criptografadas usando ChaCha20-Poly1305
- **⚡ Efêmero**: Mensagens não são armazenadas, apenas transmitidas em tempo real
- **🔑 Autenticação**: Proteção de sessões com senha (SHA-256)
- **🌐 Zero Configuração**: Não precisa mexer em roteador ou hospedar servidor
- **🚀 Relay Público**: Conecta automaticamente em servidores relay da comunidade

## Instalação

### Homebrew (macOS)
```bash
brew tap phpfc/t-chat
brew install t-chat
```

### Via Cargo
```bash
cargo install --git https://github.com/phpfc/t-chat
```

### Build Manual
```bash
git clone https://github.com/phpfc/t-chat
cd t-chat
cargo build --release
```

O binário será criado em `target/release/t-chat`

## Uso Super Simples

**Zero configuração. Zero servidores. Apenas 2 comandos.**

```bash
# Terminal 1 - Alice cria sessão
./t-chat create --username Alice --password minhasenha
# 🚀 Creating new session...
# 💡 Starting embedded relay server...
# ✓ Relay running on 127.0.0.1:8080
# 📋 Session ID: abc-123-def
# 📤 Share this ID with others to let them join!

# Terminal 2 - Bob entra (conecta no relay de Alice)
./t-chat join --session abc-123-def --username Bob --password minhasenha
```

**Pronto!** Vocês estão conversando com criptografia E2E.

### Como funciona:

1. **Alice cria sessão** → Automaticamente vira relay para a sessão
2. **Bob conecta** → Usa o relay embutido de Alice
3. **Zero servidor externo** → Tudo roda nos processos dos usuários
4. **E2E Criptografado** → Mesmo Alice (relay) não vê as mensagens

---

## Como Funciona Internamente?

### Modo Automático (Padrão):

1. **Alice executa `create`**
   - Busca relays públicos disponíveis
   - Se encontrar → usa relay público
   - Se NÃO encontrar → **inicia relay embutido automaticamente**

2. **Bob executa `join`**
   - Conecta no relay (público ou de Alice)
   - Troca chaves E2E com Alice
   - Começa a conversar

### Arquitetura:

```
┌─────────────────────────────────────────────┐
│  Alice's Process                            │
│  ┌──────────────┐    ┌──────────────┐      │
│  │ Chat Client  │◄──►│ Relay Server │      │
│  │  (Alice)     │    │  (embedded)  │      │
│  └──────────────┘    └───────┬──────┘      │
└─────────────────────────────┼──────────────┘
                              │
                              │ TCP
                              │
                    ┌─────────▼──────────┐
                    │   Bob's Process    │
                    │  ┌──────────────┐  │
                    │  │ Chat Client  │  │
                    │  │    (Bob)     │  │
                    │  └──────────────┘  │
                    └────────────────────┘
```

### Segurança:

- ✅ **E2E Criptografado**: ChaCha20-Poly1305
- ✅ **Relay cego**: Não pode descriptografar mensagens
- ✅ **Zero logs**: Mensagens apenas retransmitidas, nunca armazenadas
- ✅ **Senha protegida**: Hash SHA-256

---

## Relays Públicos (Opcional)

Para melhor performance ou uso em produção, a comunidade pode hospedar relays públicos.

Ver: [RELAYS.md](RELAYS.md) para detalhes.

**Mas não é necessário!** O app funciona perfeitamente sem relays externos.

## Exemplo Completo

```bash
# Terminal 1 - Alice cria e vira relay automaticamente
./t-chat create --username Alice --password senha123
# 🚀 Creating new session...
# 🔍 Looking for public relays... None found.
# 💡 Starting embedded relay server...
# ✓ Relay running on 127.0.0.1:8080
# 📋 Session ID: abc-123-def
# 📤 Share this ID with others to let them join!

# Terminal 2 - Bob conecta
./t-chat join --session abc-123-def --username Bob --password senha123
# 🔍 Searching for available relays...
#   Trying 127.0.0.1:8080... ✓ Online
# 📥 Joining session abc-123-def...
# [Interface de chat abre]

# Agora conversem! Digite e pressione Enter. ESC para sair.
```

### Comandos Disponíveis:

```bash
# Criar sessão (auto-relay)
./t-chat create --username Alice --password senha

# Entrar em sessão
./t-chat join --session <ID> --username Bob --password senha

# Rodar apenas relay (opcional)
./t-chat server

# Usar relay específico
./t-chat create --username Alice --password senha --server IP:PORTA
./t-chat join --session <ID> --username Bob --password senha --server IP:PORTA
```

## Interface de Chat

- Digite sua mensagem e pressione `Enter` para enviar
- Pressione `Esc` para sair
- O título mostra o Session ID e seu username
- Mensagens aparecem em tempo real

## Arquitetura de Segurança

### Criptografia E2E

1. **Troca de Chaves**: Quando usuários se conectam, trocam chaves públicas X25519
2. **Derivação de Segredo**: Cada par de usuários deriva um segredo compartilhado via ECDH
3. **Criptografia**: Mensagens são criptografadas com ChaCha20-Poly1305
4. **Autenticação**: Sessões protegidas com hash SHA-256 da senha

### Modo Relay - O que o servidor vê/não vê

| O servidor PODE ver | O servidor NÃO PODE ver |
|---------------------|-------------------------|
| IDs de sessão | Senha original |
| Usernames | Conteúdo das mensagens |
| Chaves públicas | Segredos compartilhados |
| Mensagens criptografadas | Texto plano |
| IPs e horários de conexão | Chaves privadas |

### Modo P2P - Maximamente Privado

- **STUN público** vê apenas: seu IP público e porta (necessário para NAT traversal)
- **Nenhum servidor central** processa seus dados
- **Conexão direta** entre peers
- **Ninguém pode** interceptar mensagens em texto plano

## Limitações e Requisitos

### Modo Relay
- Requer servidor acessível por todos os participantes
- Sessões não persistem após o servidor reiniciar

### Modo P2P
- ⚠️ **NAT Simétrico**: Pode falhar em ~20% dos casos (redes corporativas/móveis)
- Requer STUN servers públicos acessíveis (Google STUN)
- **Nota**: Modo P2P com chat completo será implementado em breve. Atualmente o comando gera o convite e exibe instruções.

### Ambos os Modos
- Interface suporta chat em grupo (todos veem todas as mensagens)
- Máximo 2 pessoas por sessão atualmente (1-to-1)

## Melhorias Futuras

- [ ] Suporte a múltiplas salas por sessão
- [ ] Mensagens diretas 1-to-1
- [ ] Histórico de mensagens criptografado localmente
- [ ] Descoberta de peers na rede local (mDNS)
- [ ] Suporte a arquivos/imagens
- [ ] Verificação de identidade (fingerprints)

## Tecnologias Utilizadas

- **Rust**: Linguagem de programação
- **Tokio**: Runtime assíncrono
- **Clap**: Parsing de argumentos CLI
- **Ratatui + Crossterm**: Interface de usuário no terminal
- **Ring + X25519-Dalek**: Criptografia
- **Serde**: Serialização de dados

## Licença

MIT

## Contribuindo

Pull requests são bem-vindos! Para mudanças grandes, por favor abra uma issue primeiro.
