# Troubleshooting P2P Mode

## O Problema com NAT

O modo P2P tem uma limitação importante: **Alice está escutando em `0.0.0.0:8080` (porta local), mas Bob está tentando conectar ao IP público descoberto pelo STUN**.

### Por que não funciona pela internet:

1. **Alice** descobre via STUN: `131.255.163.251:61444`
2. **Alice** escuta em: `0.0.0.0:8080` (porta local diferente!)
3. **Bob** tenta conectar em: `131.255.163.251:61444` ← **porta do STUN, não do chat!**
4. ❌ Os pacotes de Bob não chegam em Alice

### Problema de NAT Simétrico

Quando Alice faz uma requisição STUN, o roteador NAT cria um mapeamento temporário:
- `192.168.x.x:8080 ↔ 131.255.163.251:61444` (para o servidor STUN apenas)

Quando Bob tenta se conectar em `131.255.163.251:61444`, o roteador não sabe para onde enviar porque esse mapeamento era específico para o STUN.

## Solução 1: Testar em Rede Local

Para testar o P2P funcionando, use endereços locais:

### Terminal 1 (Alice):
```bash
./target/release/t-chat create-p2p --username Alice --password senha --port 8080
```

**Importante**: Ignore o endereço STUN público. Alice está em `192.168.x.x:8080`

### Terminal 2 (Bob) - Editar o convite:

1. Pegue o convite que Alice gerou
2. Decodifique usando este comando Python:
```bash
# Extrai só a parte base64
echo "eyJzZXNzaW..." | base64 -d | jq
```

3. Edite manualmente o JSON:
```json
{
  "session_id": "...",
  "public_addr": "192.168.1.100:8080",  ← Substitua pelo IP local de Alice
  "password_hash": [...],
  "public_key": [...],
  "username": "Alice"
}
```

4. Re-encode:
```bash
echo '{"session_id":...}' | base64 | tr -d '\n'
```

5. Use o novo convite:
```bash
./target/release/t-chat join-p2p --username Bob --password senha --invite "tchat://NOVO_BASE64"
```

## Solução 2: Port Forwarding (Para Internet)

Se Alice quiser aceitar conexões da internet:

1. Configure port forwarding no roteador de Alice: `8080 → 192.168.x.x:8080`
2. Use o IP público de Alice (pode verificar em https://ifconfig.me)
3. Edite o convite com o IP público correto:
```json
{
  "public_addr": "SEU_IP_PUBLICO:8080"
}
```

## Solução 3: Usar Modo Relay (Recomendado)

Para simplicidade, use o modo relay que sempre funciona:

```bash
# Terminal 1 - Servidor
./target/release/t-chat server

# Terminal 2 - Alice
./target/release/t-chat create --username Alice --password senha

# Terminal 3 - Bob
./target/release/t-chat join --session <ID> --username Bob --password senha
```

## Melhorias Futuras Necessárias

Para P2P funcionar corretamente pela internet, precisamos:

1. **ICE (Interactive Connectivity Establishment)**
   - Combina STUN + TURN
   - Testa múltiplos caminhos de conexão
   - Fallback automático

2. **TURN Server (Relay Fallback)**
   - Quando P2P direto falha
   - Servidor relay temporário
   - Mantém criptografia E2E

3. **Descoberta de porta correta**
   - Após STUN, fazer bind na mesma porta local
   - Ou usar a porta que o STUN reportou

4. **Session Description Protocol (SDP)**
   - Trocar informações de rede entre peers
   - Incluir candidatos ICE
   - Similar ao WebRTC

## Teste Rápido de Conectividade

Verifique se Bob consegue alcançar Alice:

```bash
# No computador de Bob
nc -u <IP_DE_ALICE> 8080
# Digite algo e pressione Enter
# Se Alice receber, a conexão funciona!
```

## Status Atual

✅ **Funciona em rede local**
❌ **Não funciona pela internet** (sem port forwarding)
✅ **Modo relay sempre funciona**

## Recomendação

Para uso imediato pela internet, use o **modo relay**:
- Sempre funciona
- Não requer configuração de rede
- Ainda mantém criptografia E2E
- Apenas requer um servidor simples
