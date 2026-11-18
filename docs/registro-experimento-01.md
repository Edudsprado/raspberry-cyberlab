# Registro complementar do experimento 01

Este documento orienta a recuperação dos dados que ainda faltam na metodologia.
Os campos pendentes não devem ser preenchidos com comandos reconstruídos por suposição.

## Dados já verificados

- Arquivo analisado no Windows: `experimento-nmap.pcap`, 160.208 bytes.
- SHA-256: `ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e`.
- 2.002 pacotes TCP/IPv4; endpoints observados em loopback (`127.0.0.1`).
- Porta 22: handshake completo nos pacotes 19–21; porta 23: SYN/RST-ACK nos pacotes 31–32.

## Etapa 1 — localizar os comandos originais

No PowerShell do Windows, conecte ao Raspberry com o usuário e o endereço do
equipamento na sua rede de laboratório. Substitua os valores de exemplo.

```powershell
ssh USUARIO@ENDERECO_DO_RASPBERRY
```

Depois de entrar, execute no terminal do Raspberry (Bash):

```bash
history | grep -E 'nmap|tcpdump'
```

Registre as linhas relevantes sem executar novamente a varredura ou a captura.
A própria linha de busca pode aparecer no resultado. Se não houver histórico,
registre a ausência; ela não permite concluir quais comandos foram usados.

Um histórico sem data e sem saída associada fornece candidatos, mas não prova
sozinho qual execução produziu o PCAP. Relacione as linhas com o nome do arquivo,
saída salva do Nmap, anotações ou capturas de tela do experimento original.

### Primeira busca: saída informada pelo usuário

O usuário forneceu a saída de `history | grep -E 'nmap|tcpdump'` no terminal
`cyber@raspberrypi`, com diretório apresentado como `~/Cyberlab/capturas`.
Essa informação foi recebida por texto; não houve coleta remota direta nesta etapa.

- Linha 40: `tcpdump --version` (sem saída de versão nesta transcrição).
- Linha 42: `sudo tcpdump -i eth0 -c 20 -nn -w capturas/teste-inicial.pcap`.
- Linhas 51 e 52: leitura de `teste-inicial.pcap`, com diferença de maiúsculas
  entre os caminhos `/home/cyber/cyberlab` e `/home/cyber/Cyberlab`.
- Linha 113: comando SCP que menciona `experimento-nmap.pcap`; não é comando
  de captura ou varredura e não comprova, sozinho, transferência bem-sucedida.
- Linha 114: a própria busca no histórico.

Não aparece um comando Nmap nem um tcpdump gravando `experimento-nmap.pcap`.
A interface `eth0` na linha 42 se refere a `teste-inicial.pcap`; não foi atribuída
ao PCAP de 2.002 pacotes. As pendências do experimento 01 permanecem abertas.

### Buscas complementares: saídas fornecidas pelo usuário

```bash
grep -nE 'nmap|tcpdump' ~/.bash_history
sudo grep -nE 'nmap|tcpdump' /root/.bash_history
```

A busca em `~/.bash_history` retornou as linhas 40, 42, 51 e 52 do teste inicial,
uma linha SCP (90) e uma linha `Get-FileHash` (91). Não retornou comando Nmap
ou tcpdump gravando o PCAP principal. As linhas de SCP e `Get-FileHash` no histórico
não demonstram, por si, execução bem-sucedida desses comandos.

A consulta a `/root/.bash_history` retornou exatamente:

```text
grep: /root/.bash_history: No such file or directory
```

Conclusão desta etapa: os comandos originais não foram recuperados nas fontes
consultadas. Isso não comprova que nunca tenham sido executados. A interface
original continua não identificada. A análise do PCAP permanece válida dentro
do escopo documentado; o comando e a técnica exata da varredura não foram confirmados.
Não se atribui `eth0` nem um comando Nmap presumido à captura principal.

## Etapa 2 — registrar o ambiente atual

Execute separadamente, depois da revisão do histórico:

```bash
tr '\0' '\n' < /proc/device-tree/model
cat /etc/os-release
uname -r
python3 --version
nmap --version
tcpdump --version
```

O primeiro comando pode não existir fora de um Raspberry. Esses comandos medem
o ambiente **no momento desta coleta**; não comprovam que as mesmas versões
estavam instaladas na data da captura.

### Modelo informado pelo usuário

Após a orientação para consultar `/proc/device-tree/model`, o usuário forneceu:

```text
Raspberry Pi 3 Model B Rev 1.2
```

Registrado como identificação do equipamento consultado nesta etapa, a partir
da transcrição fornecida pelo usuário, sem acesso remoto direto. O modelo não
foi inferido do PCAP.

### Sistema operacional informado pelo usuário

O usuário forneceu a transcrição de `cat /etc/os-release`, com os campos:

```text
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
DEBIAN_VERSION_FULL=13.7
ID=debian
```

Esses valores identificam o sistema conforme o arquivo consultado na coleta
atual. São informações fornecidas pelo usuário, sem acesso remoto direto ou
verificação independente da imagem instalada.

### Kernel informado pelo usuário

Após a orientação para executar `uname -r`, o usuário forneceu:

```text
6.18.50+rpt-rpi-v8
```

Registrado como versão do kernel na coleta atual, conforme transcrição fornecida
pelo usuário, sem acesso remoto direto.

### Python informado pelo usuário

Após a orientação para executar `python3 --version`, o usuário forneceu:

```text
Python 3.13.5
```

A versão atende ao requisito Python 3.10+ do analisador. Os resultados da
execução posterior dos testes no Raspberry estão registrados abaixo.

### Nmap informado pelo usuário

O usuário forneceu a saída de `nmap --version`:

```text
Nmap version 7.95 ( https://nmap.org )
Platform: aarch64-unknown-linux-gnu
Compiled with: liblua-5.4.7 openssl-3.5.7 libssh2-1.11.1 libz-1.3.1 libpcre2-10.46 libpcap-1.10.5 nmap-libdnet-1.12 ipv6
Compiled without:
Available nsock engines: epoll poll select
```

Registrado como versão instalada na coleta atual, conforme transcrição fornecida
pelo usuário. Essa saída não recupera o comando original da varredura nem confirma
a versão usada para gerar o PCAP.

### tcpdump informado pelo usuário

O usuário forneceu a saída de `tcpdump --version`:

```text
tcpdump version 4.99.5
libpcap version 1.10.5 (with TPACKET_V3)
OpenSSL 3.5.7 9 Jun 2026
64-bit build, 64-bit time_t
```

Com isso, o registro das versões atuais do Python, Nmap e tcpdump está completo.
A data na linha do OpenSSL identifica a versão da biblioteca, não a data da coleta
ou da captura. A versão usada no experimento original não foi confirmada.

A interface original deve ser registrada a partir do comando tcpdump ou de outro
registro da coleta. O enlace Ethernet do PCAP e os IPs de loopback não revelam,
isoladamente, o nome da interface utilizado no comando.

### Nova conferência dos PCAPs no Raspberry

O usuário forneceu a saída de `sha256sum "$HOME"/Cyberlab/capturas/*.pcap`:

```text
ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e  /home/cyber/Cyberlab/capturas/expermiremnto-nmap.pcap
6b9fd075069801bbae41fcf00dcf805e2a30945cdea718e10590553b2945e8d8  /home/cyber/Cyberlab/capturas/teste-inicial.pcap
```

O hash informado para `expermiremnto-nmap.pcap` coincide com o recalculado
localmente no Windows para `experimento-nmap.pcap`. Os nomes são diferentes;
o conteúdo é compatível com a mesma evidência pela comparação SHA-256.
O caminho do Raspberry fica registrado com a grafia efetivamente apresentada,
sem renomear a evidência. `teste-inicial.pcap` é outro arquivo, com outro hash.
Essa nova conferência remota foi fornecida pelo usuário por transcrição.

## Campos a completar com as evidências recuperadas

| Campo | Situação |
| --- | --- |
| Comando Nmap original | Não recuperado nos históricos consultados |
| Comando tcpdump original | Não recuperado nos históricos consultados |
| Interface de captura original | Não identificada nas fontes consultadas |
| Caminho atual do PCAP no Raspberry | /home/cyber/Cyberlab/capturas/expermiremnto-nmap.pcap — nova saída de sha256sum fornecida pelo usuário; hash coincide com o PCAP analisado no Windows |
| Modelo do Raspberry | Raspberry Pi 3 Model B Rev 1.2 — saída fornecida pelo usuário na coleta atual |
| Sistema operacional e versão atuais | Debian GNU/Linux 13 (trixie); DEBIAN_VERSION_FULL=13.7 — transcrição de /etc/os-release fornecida pelo usuário |
| Kernel atual | 6.18.50+rpt-rpi-v8 — saída fornecida pelo usuário para uname -r |
| Python atual | 3.13.5 — saída fornecida pelo usuário para python3 --version |
| Nmap atual | 7.95; plataforma aarch64-unknown-linux-gnu — saída fornecida pelo usuário para nmap --version |
| tcpdump atual | 4.99.5; libpcap 1.10.5 com TPACKET_V3; OpenSSL 3.5.7; build e time_t de 64 bits — saída fornecida pelo usuário |
| Data e fonte de cada informação recuperada | Pendente |
| Correspondência dos comandos encontrados com este PCAP | Pendente de confirmação documental |

## Transferência e testes no Raspberry

Foi preparado localmente o pacote `cyberlab-analyzer-0.1.0.zip`, com 18 arquivos
de código, testes e documentação, sem PCAPs ou relatórios completos. SHA-256:

```text
f62467262628ea4434f8befd02b7951e69a056439a0eadce6472ce5112814ecc
```

O usuário forneceu a saída do SCP com transferência a 100%, uma conferência
`sha256sum` no Raspberry com esse mesmo hash e a extração via
`python3 -m zipfile -e`, sem erro apresentado. Esse hash identifica o pacote
transferido naquele momento; atualizações posteriores da documentação local
não alteram o pacote já validado.

Na sequência, forneceu a saída de testes executados em
`/home/cyber/Cyberlab/cyberlab-analyzer-0.1.0`, com `CYBERLAB_TEST_PCAP` apontando
para `/home/cyber/Cyberlab/capturas/expermiremnto-nmap.pcap`:

```text
Ran 21 tests in 0.518s

OK (skipped=1)
```

Foram 20 testes aprovados e 1 ignorado: comparação com TShark indisponível.
Os dois testes sobre o PCAP real passaram. Consulte a
[validação](validacao.md) e o [log transcrito](evidencias/unittest-raspberry-transcrito.txt).
As saídas remotas foram fornecidas pelo usuário; não houve acesso remoto direto.

## Execução do analisador sobre o PCAP real no Raspberry

O usuário forneceu a execução de `python3 -m cyberlab` com o caminho confirmado
da evidência, `--output-dir relatorios-raspberry-01` e `--expect-sha256` com o hash
do experimento 01. A saída registra:

- CyberLab 0.1.0; 2.002 pacotes e 2.002 TCP.
- SHA-256 esperado: `ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e`.
- 1 tentativa aberta, 999 fechadas e nenhum pacote ignorado.
- Geração informada de `relatorio.json`, `portas.csv`, `tentativas.csv` e
  `fluxos-tcp.csv` em `relatorios-raspberry-01`.

Os totais coincidem com os resultados obtidos diretamente no Windows.
O [log transcrito](evidencias/cli-raspberry-transcrito.txt) identifica a fonte.
O usuário forneceu depois as linhas selecionadas de `portas.csv`, confirmando:

| IP de destino | Porta | Classificação | Tentativas | ID |
| --- | --- | --- | --- | --- |
| 127.0.0.1 | 22 | aberta | 1 | 10 |
| 127.0.0.1 | 23 | fechada | 1 | 15 |

Os IDs e classificações coincidem com a execução no Windows. A
[seleção transcrita do CSV](evidencias/portas-raspberry-transcrito.txt) preserva
os campos fornecidos pelo usuário.

Os quatro arquivos foram posteriormente recebidos no Windows na pasta
`relatorios-raspberry-recebidos`. A comparação direta com `relatorios-validacao`
confirmou que os três CSVs são idênticos byte por byte, com 1.000 linhas em
`portas.csv`, 1.000 em `tentativas.csv` e 2.000 em `fluxos-tcp.csv`.
No JSON, somente `analyzed_at_utc` e `source.name` diferem: os horários de execução
e os nomes de arquivo são próprios de cada ambiente. Todos os demais valores
coincidem. O [registro estruturado](evidencias/comparacao-windows-raspberry.json)
inclui os hashes calculados diretamente para os relatórios recebidos e locais.

## Etapa seguinte

Preparar a entrega acadêmica com a validação técnica concluída no Windows e no
Raspberry dentro dos limites documentados. A validação no Kali não foi executada.
Os comandos originais da captura e varredura permanecem não recuperados nas
fontes consultadas e devem ser tratados como limitação, não como fatos presumidos.
