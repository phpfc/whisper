# whisper: conexão P2P sem custo de infraestrutura

Data: 2026-11-20
Status: rascunho para aprovação

## Intenção

O whisper é um chat de terminal 1-para-1, criptografado ponta a ponta. O projeto foi
abandonado porque a conexão não funcionava pela internet. O objetivo agora é que dois
peers se conectem diretamente, com um único código compartilhado, sem que o usuário
configure nada na rede, e **sem custo de infraestrutura**: nenhum servidor que o projeto
precise hospedar, manter ou pagar.

A regra é custo, não "zero terceiros". Serviços públicos e gratuitos que ninguém do
projeto mantém são permitidos: servidores STUN do Google/Cloudflare e a DHT do BitTorrent
(Mainline). Relay de dados continua proibido, mesmo gratuito.

"Setup invisível" significa sem configuração manual, não escondido: o app mexe na rede
sozinho (abre porta no roteador) e mostra o que fez.

## Objetivos

1. Um código só, enviado de quem cria para quem entra, por qualquer canal (WhatsApp etc.).
2. Nenhuma configuração manual de rede: sem port forwarding, sem mexer em firewall.
3. O peer que tiver rede melhor vira host automaticamente, seja quem criou ou quem entrou.
4. IPv4 e IPv6.
5. Quando a conexão direta for impossível, falhar com uma mensagem que diga a causa.
6. Um comando `whisper doctor` que diagnostica a rede, usado para medir a cobertura real
   nas redes de quem vai usar o app e para explicar falhas.

## Não-objetivos

- Chat em grupo, mensagens offline, apps móveis.
- Atravessar NAT simétrico dos dois lados (exigiria relay).
- Previsão de portas / "birthday attack" para NAT simétrico.
- Compatibilidade com códigos da v0.2 (a v0.2 não conecta pela internet de qualquer forma).
- Publicar ou consertar o pacote Chocolatey.

## Anti-objetivos (falha mesmo que funcione)

- Qualquer servidor que o projeto precise hospedar ou pagar, incluindo relay ou TURN.
- Chave de conta paga (Cloudflare, Metered etc.) embutida no binário.
- Abrir porta no roteador sem avisar o usuário, ou deixá-la aberta depois que o app sai
  normalmente. (Se o processo morrer, o mapeamento aponta para uma porta fechada e expira
  sozinho; ver "Abertura de porta no roteador".)
- Fallback silencioso para modo local ou para um estado quebrado.

## Estado atual (o que existe e o que está errado)

- `src/stun.rs`: consulta STUN escrita à mão, só IPv4 (`stun.rs:21` faz bind em
  `0.0.0.0`, `stun.rs:42` descarta endereços IPv6). O socket da consulta é reaproveitado
  no chat, o que está certo.
- `src/hole_punch.rs`: **causa principal da falha da v0.2.** `wait_for_peer`
  (`hole_punch.rs:36`) só escuta; quem cria nunca envia pacotes para quem entra. Roteadores
  com filtragem dependente de endereço/porta (a classe mais comum, "port-restricted cone")
  descartam os pacotes de quem entra, porque quem criou só falou com o servidor STUN.
- `src/session/mod.rs`: código no formato `<ip>:<porta>#<session_id>#<salt>`.
  `SessionAuth` calcula Argon2id da senha, mas o resultado nunca é usado
  (`main.rs:169`, `_auth`): a troca de chaves X25519 não é autenticada.
- `src/crypto/mod.rs`: X25519 + ChaCha20-Poly1305 (ring), nonce com contador.
- `src/cli/mod.rs`: UI ratatui síncrona, threads, keepalive a cada 15 s.
- `src/cli/p2p.rs`: código morto (fora da árvore de módulos, importa o módulo `invite`
  que foi removido).
- A v0.1 usou UPnP (`igd-next`), mas para o relay TCP, não para o caminho P2P UDP.
- Docs obsoletos que descrevem o modelo de relay e contradizem o princípio:
  `P2P_TROUBLESHOOTING.md`, `RELAYS.md`, `DEPLOY.md`.
- `chocolatey/tools/chocolateyinstall.ps1` está desatualizado (versão 0.1.0, checksum
  `PLACEHOLDER_SHA256`, URL sem a versão no nome do arquivo, diferente do que o workflow
  de release gera).

## Abordagens consideradas

| | Como resolve "quem criou não consegue ser host" | Troca |
|---|---|---|
| **A. Só host com porta aberta** | Erro: "peça para o outro criar a sessão" | Menor código, nenhum serviço externo; deixa de fora CGNAT sem IPv6; troca de papéis manual |
| **B. A + código de resposta manual** | Quem entra manda um segundo código de volta; hole punching com STUN | Cobre mais redes; dois copiar-e-colar, contra o "setup invisível" |
| **C. A + troca automática pela DHT do BitTorrent** | Os dois publicam seus endereços, cifrados, na Mainline DHT; quem pode hospedar vira host, senão hole punching | Um código só e papéis automáticos; dependência nova (crate `mainline`) e alguns segundos a mais |

Descartadas: TURN público gratuito (os bons exigem conta, cuja chave iria no binário e
seria abusada; os sem conta são instáveis) e relay por um terceiro peer (exige uma terceira
pessoa online).

**Escolhida: C**, construída em camadas (A é a primeira camada de C). Motivo: é a única
que mantém um código só e escolhe o host sozinha sem nenhum servidor do projeto.

## Design

### Visão geral

Cada peer coleta **candidatos** (endereços onde talvez possa ser alcançado). Os candidatos
de quem cria vão em parte no código e por inteiro na DHT; os de quem entra vão na DHT.
Os dois testam todos os pares de candidatos ao mesmo tempo, nos dois sentidos. O primeiro
par que completa o handshake vira o caminho do chat. "Host" não é um papel negociado: é
simplesmente o lado cujo candidato funcionou.

```
quem cria                                   quem entra
coleta candidatos ─┐                ┌─ coleta candidatos
mostra o código ───┼── (WhatsApp) ──┼─> lê o código, já testa os candidatos dele
publica "c" na DHT │                │   publica "j" na DHT, lê "c"
lê "j" da DHT ─────┘                └─
        └──── testes simultâneos em todos os pares (hole punching) ────┘
                       primeiro par com handshake ok = chat
```

### Candidatos

Sockets: um UDP IPv4 (`0.0.0.0:0`) e um UDP IPv6 (`[::]:0`, `IPV6_V6ONLY`). O mesmo socket
é usado para STUN, para o mapeamento de porta e para o chat, para que os mapeamentos
correspondam.

| Tipo | Origem | Observação |
|---|---|---|
| `ipv6` | Endereços IPv6 globais (2000::/3) das interfaces + porta do socket IPv6 | Sem NAT. O firewall do roteador pode bloquear entrada não solicitada; os testes simultâneos resolvem isso quando há sinalização pela DHT |
| `mapped` | Porta aberta no roteador via UPnP-IGD, NAT-PMP ou PCP; o roteador informa o IP externo | Só vale se o IP externo for público. Se for privado (RFC 1918) ou CGNAT (100.64.0.0/10), há NAT duplo e o candidato é descartado |
| `reflexive` | IPv4:porta visto pelo STUN | Útil só com testes simultâneos (precisa da DHT) |
| `lan` | IPv4 privado das interfaces + porta | Peers na mesma rede local |

Além disso, ao receber um teste de um endereço que não estava na lista (o NAT do outro lado
escolheu outra porta), responde-se para esse endereço de origem e ele vira um candidato
("peer-reflexive"). Isso cobre o caso de um lado com NAT simétrico e o outro com filtragem
só por endereço.

### Abertura de porta no roteador

- Crate: `portmapper` (n0-computer, MIT/Apache-2.0, usado pelo iroh). Suporta UPnP, PCP e
  NAT-PMP e mantém o mapeamento durante mudanças de rede. Exige Rust ≥ 1.89 no toolchain.
- Mapeia a porta UDP local do socket IPv4 e remove o mapeamento ao sair (ESC, Ctrl-C via
  handler de sinal, fim normal).
- **Decisão (minha):** aceitar o prazo fixo de 2 h que o `portmapper` pede ao roteador
  (constante `PORT_MAPPING_LEASE_DURATION_SECONDS`, não configurável). Um prazo de 10 min
  exigiria fork do crate ou montar sobre `igd-next` + `crab_nat`, perdendo o tratamento de
  mudança de rede. O custo aceito: se o processo morrer sem limpar, o mapeamento fica até
  2 h apontando para uma porta onde nada escuta.
- Roteadores UPnP antigos que só aceitam prazo permanente (erro 725) ficam sem mapeamento;
  o caminho pela DHT cobre esses casos. Não se cria mapeamento permanente.
- Mostra ao usuário, por exemplo: `UDP port 54321 opened on your router (closed on exit)`.
  O crate não informa qual protocolo funcionou, então a mensagem não cita o protocolo.
- Quem cria tenta mapear. Quem entra também tenta, porque pode ser quem vira host.
- Nenhum desses protocolos exige privilégio de administrador.

### Formato do código (v3)

`base58(versão=3 || segredo[16] || candidatos diretos)`

- `segredo`: 128 bits aleatórios. Dele derivam (HKDF-SHA256, com rótulos distintos): a
  chave Ed25519 dos registros na DHT, a chave de cifra dos registros, a chave de
  autenticação dos testes, o salt do Argon2id e a base da chave do handshake.
- `candidatos diretos`: só os que funcionam sem sinalização, para quem entra conectar na
  hora mesmo antes da DHT responder: o `mapped` e, se houver, um `ipv6` e um `lan`.
  Codificação binária compacta (IPv4+porta = 6 bytes, IPv6+porta = 18 bytes).
- Tamanho esperado: ~25 caracteres sem candidatos, ~60–90 com. O salt sai do código
  (derivado do segredo).
- O byte de versão permite mudar o formato depois.

### Sinalização pela Mainline DHT

- Crate: `mainline` (BEP44, modo cliente, funciona atrás de NAT). Nós de bootstrap padrão
  do BitTorrent: públicos e gratuitos.
- Dois itens mutáveis BEP44 com a mesma chave Ed25519 (derivada do segredo) e salts
  diferentes: `c` (quem cria) e `j` (quem entra). Os dois peers conseguem assinar, então
  não há troca de chave.
- Conteúdo: cifrado com a chave de registro (ChaCha20-Poly1305, nonce aleatório) contendo
  a lista completa de candidatos e um resumo da rede (pode hospedar? NAT simétrico?),
  usado na mensagem de erro do outro lado. Limite do BEP44: 1000 bytes.
- Quem cria publica `c` assim que coleta os candidatos (em segundo plano, o código aparece
  antes) e consulta `j` a cada poucos segundos. Quem entra publica `j` logo ao ler o código
  e consulta `c`. Ao mudar candidatos, republica com `seq` maior.
- Os nós da DHT veem um bloco cifrado e o IP de quem consulta, mais ou menos o que o STUN
  já vê. Sem o código, não dá para achar nem ler o registro.

### Testes de conectividade e hole punching

- Cada lado envia um `Probe` para cada candidato remoto a cada ~200 ms. Quem recebe
  responde `ProbeAck` para o **endereço de origem** do pacote.
- `Probe`/`ProbeAck` levam uma tag HMAC derivada do segredo. Pacotes sem tag válida são
  ignorados sem resposta. Isso impede que scanners provoquem respostas na porta aberta e
  que o app sirva de refletor.
- O primeiro par com ida e volta confirmada é usado. Se vários confirmarem quase juntos,
  prefere `lan` > `ipv6` > `mapped` > `reflexive` (janela curta de desempate, a critério
  de quem construir).
- Timeouts: quem cria espera até 10 min por alguém (tempo de copiar e colar o código).
  Quem entra desiste após ~45 s de testes com os dois conjuntos de candidatos em mãos, ou
  ~60 s se a DHT nunca trouxer o registro de quem criou.
- Keepalive de 15 s mantido.

### Handshake autenticado (decisão minha)

Hoje a senha não protege nada. Como o protocolo de rede vai ser reescrito de qualquer jeito,
o handshake é trocado agora, em vez de mexer duas vezes:

- Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s` via crate `snow` (já sugerido em `tips.md`).
- PSK = HKDF(segredo do código || Argon2id(senha, salt derivado do segredo)). Sem senha, o
  Argon2id entra com senha vazia, e o segredo de 128 bits do código autentica sozinho.
- **Senha opcional (decisão minha):** `-p` deixa de ser obrigatório. O código já carrega
  128 bits de segredo, o que cumpre o objetivo "um código só". A senha vira proteção extra
  para quem quiser mandá-la por outro canal; se usada, os dois lados precisam informá-la.
- Senha ou código errados fazem o handshake falhar: mostra "wrong password or invalid code".
- Transporte UDP com nonce explícito (`snow` tem modo stateless para isso), substituindo o
  `CryptoSession` atual. O fingerprint continua sendo exibido.

### Firewall do sistema operacional

**Decisão (minha):** nenhuma regra de firewall é criada, nem no instalador nem pelo app.

- O pacote Chocolatey nunca foi publicado (o workflow de release não gera pacote e a página
  do pacote não existe); usuários Windows baixam o zip. Uma regra no script do Chocolatey
  não chegaria a ninguém, e criar a regra pelo app exigiria o prompt de administrador, o
  oposto de "setup invisível". Publicar no Chocolatey fica fora de escopo.
- O que garante a conexão é o envio de saída: assim que um lado conhece os candidatos do
  outro (pela DHT), ele envia para eles, e os firewalls stateful (Windows, macOS, Linux)
  aceitam a resposta sem regra.
- Custo aceito: num host Windows, o caminho rápido (quem entra conecta direto pelo
  candidato do código) pode ser bloqueado pelo firewall do Windows. O Windows trata redes
  novas como "Públicas", e o prompt da primeira execução libera só redes "Privadas" por
  padrão. Nesse caso, a conexão espera a rodada da DHT. Documentar no README.
- macOS: o firewall de aplicativos vem desligado por padrão. Linux desktop raramente
  bloqueia entrada. Só documentar.

### `whisper doctor`

Diagnóstico da rede, sem conectar a ninguém. Exemplo do que mostra:

```
IPv6 global:        sim (2804:14c:…)
Roteador:           UPnP ✓   NAT-PMP ✗   PCP ✗   IP externo 189.40.x.x
CGNAT:              não (IP do roteador = IP visto pelo STUN)
NAT:                mapeamento independente do destino (bom para hole punching)
DHT:                alcançável (2,1 s)
Veredito:           pode hospedar sessões ✓
```

- Teste de NAT simétrico: duas consultas STUN a servidores com IPs diferentes, a partir do
  mesmo socket. Portas iguais = mapeamento independente do destino; diferentes = simétrico.
- CGNAT: IP externo do roteador em 100.64.0.0/10 ou faixa privada, ou diferente do IP visto
  pelo STUN.
- A abertura de porta feita pelo diagnóstico é removida antes de sair.
- Reaproveita o mesmo código da coleta de candidatos. Serve para medir a cobertura real com
  amigos (eles rodam e mandam a saída) e para as mensagens de erro.

### Mensagens de falha

Com o resumo de rede que vem pela DHT, o erro diz a causa, por exemplo: "Sem caminho direto:
você está atrás de CGNAT com NAT simétrico e a rede do outro peer também não permite
hospedar. Tente outra rede (Wi-Fi em vez de 4G) ou rode `whisper doctor`." Se a DHT estiver
inacessível e o código não tiver candidatos diretos, dizer isso.

## Ordem de construção

**Decisão (minha):** um plano só, até a abordagem C completa, sem release obrigatória entre
as etapas e sem esperar medição. A abordagem C já foi escolhida, então os resultados do
`doctor` servem para ajustar detalhes, não para decidir se a DHT entra. Se quiser mandar o
`doctor` para amigos antes, ele pode sair numa release própria ao fim da etapa 1, mas nada
depende disso. Como não há release da etapa 2 sozinha, ela não precisa de uma mensagem de
erro própria do tipo "peça para o outro criar a sessão".

1. **Coleta de candidatos + abertura de porta + `whisper doctor`.** Base de tudo, e já
   permite medir redes reais.
2. **Conexão direta.** Código v3 com candidatos diretos, testes nos dois sentidos, IPv6,
   handshake autenticado.
3. **Sinalização pela DHT.** Registros `c`/`j`, hole punching entre dois NATs, inversão
   automática de papéis, mensagens de falha com o resumo do outro lado.
4. **Documentação e limpeza.** Atualizar `README.md` (incluindo o comportamento do firewall
   do Windows) e `ARCHITECTURE.md` (o princípio passa a ser "zero custo de infra"; STUN e
   DHT públicos permitidos), apagar `P2P_TROUBLESHOOTING.md`, `RELAYS.md`, `DEPLOY.md` e
   `src/cli/p2p.rs`.

## Idioma da interface

**Decisão (minha):** a interface continua em inglês, como o app e o README atuais (o
projeto é distribuído por Homebrew e GitHub). Os exemplos em português neste documento
são ilustrativos.

## Critérios de sucesso

- Dois peers com IPv6 se conectam com um código, sem nenhuma pergunta do sistema.
- Quem cria atrás de roteador com UPnP, em macOS ou Linux: quem entra conecta direto, sem
  esperar a DHT, em menos de 5 s depois de colar o código. Em host Windows sem liberação
  no firewall, conecta após a rodada da DHT (até ~20 s).
- Os dois atrás de CGNAT com mapeamento independente do destino, sem IPv6: conectam pela DHT
  + hole punching em até ~20 s.
- Os dois com NAT simétrico: falha explícita em até ~60 s, com a causa.
- Nenhuma porta fica mapeada no roteador depois que o app sai.
- Nenhum servidor do projeto em nenhum caminho.

## Testes

- Unitários: codificação/decodificação do código v3; classificação de endereços (público,
  privado, CGNAT, link-local); derivação de chaves determinística; cifra dos registros e
  limite de 1000 bytes; validação da tag dos testes.
- Integração local: dois processos na mesma máquina conectando por `lan` sem DHT; conexão
  pela DHT usando uma DHT local de teste (verificar se o crate `mainline` oferece testnet).
- Simulação de NAT no Linux (CI, ubuntu): network namespaces com `iptables MASQUERADE` para
  NAT "port-restricted" e `--random-fully` para NAT simétrico, cobrindo as combinações da
  tabela de critérios.
- Matriz manual: fibra com IPv6, roteador com UPnP, 4G (CGNAT), Wi-Fi de empresa ou
  universidade.

## Deixado para quem construir

- Async (tokio, já é dependência) versus threads na fase de conexão. `portmapper` é async;
  a UI pode continuar síncrona.
- Serialização dos pacotes na rede (hoje JSON) e dos registros na DHT.
- Detalhes de cadência e desempate dos testes de conectividade.
- Se `portmapper` abre pinhole IPv6 via PCP; se não abrir, o IPv6 depende dos testes
  simultâneos pela DHT.
- Apagar ou sobrescrever os registros da DHT ao sair (eles expiram sozinhos em ~2 h e são
  ilegíveis sem o código).
