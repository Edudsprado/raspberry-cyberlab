# Experimento 01 — análise do PCAP real

Projeto: Raspberry CyberLab. Análise executada em **17/11/2026**, no Windows,
com Python 3.12.3 e CyberLab Forensic Analyzer 0.1.0.
O PCAP foi lido de Downloads, sem alteração do conteúdo.

## Identificação da evidência

| Campo | Valor medido |
| --- | --- |
| Arquivo | `experimento-nmap.pcap` |
| Tamanho | 160.208 bytes |
| SHA-256 | `ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e` |
| Formato | PCAP clássico 2.4, little endian, Ethernet, microssegundos |
| Pacotes / TCP/IPv4 | 2.002 / 2.002 |
| Primeiro timestamp (UTC) | 2026-11-17 13:50:50.902836 |
| Último timestamp (UTC) | 2026-11-17 13:50:50.989447 |
| Intervalo entre extremos | 0,086611 segundo |
| Pacotes ignorados / truncados / regressões temporais | 0 / 0 / 0 |

Em America/Cuiaba (UTC−04), o início equivale a 09:50:50.902836. Esses horários
são os registrados na captura; não foi verificada a sincronização do relógio de origem.

O SHA-256 calculado coincide com o valor apresentado pelo usuário na conversa
anterior para o Raspberry e para a cópia no Windows. Na coleta complementar,
o usuário forneceu uma nova saída de `sha256sum`, com o mesmo hash para
`/home/cyber/Cyberlab/capturas/expermiremnto-nmap.pcap` no Raspberry. Essa é a
grafia efetivamente informada no sistema de origem; a cópia do Windows tem o nome
`experimento-nmap.pcap`. O hash do Windows foi recalculado diretamente nesta
máquina; a conferência do Raspberry foi recebida por transcrição do usuário,
sem acesso remoto direto. O hash não autentica sozinho a origem da captura.

## Ambiente informado na coleta complementar

O usuário forneceu transcrições dos comandos de identificação executados no
Raspberry. Não houve acesso remoto direto nesta etapa. Os dados descrevem o
ambiente consultado agora; as versões na data da captura não foram confirmadas.

| Item | Valor informado |
| --- | --- |
| Equipamento | Raspberry Pi 3 Model B Rev 1.2 |
| Sistema operacional | Debian GNU/Linux 13 (trixie); DEBIAN_VERSION_FULL=13.7 |
| Kernel | 6.18.50+rpt-rpi-v8 |
| Python | 3.13.5 |
| Nmap | 7.95; plataforma aarch64-unknown-linux-gnu |
| tcpdump | 4.99.5 |
| libpcap do tcpdump | 1.10.5, com TPACKET_V3 |
| OpenSSL do tcpdump | 3.5.7, com data de versão 9 Jun 2026 |
| Build do tcpdump / time_t | 64 bits / 64 bits |

As transcrições e suas limitações estão no
[registro complementar](registro-experimento-01.md). A saída de testes fornecida
pelo usuário para o Raspberry registra 21 testes descobertos: 20 aprovados e
1 ignorado por ausência do TShark, em 0,518 s. Os dois testes sobre o PCAP real
passaram. A saída de execução posterior fornecida pelo usuário registra a
geração de JSON e três CSVs em `relatorios-raspberry-01`, com 2.002 pacotes TCP,
1 tentativa aberta, 999 fechadas, nenhum pacote ignorado e o mesmo SHA-256
observado no Windows. A comparação independente com TShark foi executada no Windows.
Os quatro relatórios foram posteriormente recebidos e comparados diretamente:
os três CSVs são idênticos byte por byte aos do Windows; no JSON, somente o
horário da análise e o nome do arquivo de entrada diferem. O
[registro da comparação](evidencias/comparacao-windows-raspberry.json) documenta os resultados.

## Resultados das tentativas

Foram identificadas **1.000 tentativas** para 1.000 portas TCP de destino distintas,
com cliente e destino em `127.0.0.1`. Houve **uma tentativa aberta e 999 fechadas**
segundo os padrões de handshake registrados. Foram resumidos 2.000 fluxos direcionais.
Não se afirma que todas as 65.535 portas foram examinadas.

| Porta de destino | Evidência | Resultado observado |
| --- | --- | --- |
| 22/TCP | Pacotes 19 → 20 → 21 | SYN → SYN/ACK → ACK: aberta |
| 23/TCP | Pacotes 31 → 32 | SYN → RST/ACK: fechada |

### Porta 22: handshake completo

| Pacote | Direção (ambos IPs 127.0.0.1) | Flags | SEQ absoluto | ACK absoluto |
| --- | --- | --- | --- | --- |
| 19 | 47552 → 22 | SYN | 4173570263 | 0 |
| 20 | 22 → 47552 | SYN, ACK | 3856505152 | 4173570264 |
| 21 | 47552 → 22 | ACK | 4173570264 | 3856505153 |
| 22 | 47552 → 22 | RST, ACK | 4173570264 | 3856505153 |

O pacote 20 reconhece o SYN do cliente; o 21 reconhece o SYN do destino. O pacote
22 é um reset posterior enviado pelo iniciador e não transforma a tentativa em
fechada. Ele entra no resumo TCP e no contador de controle SYN/RST não correlacionado
ao estabelecimento; esse contador é 1 nesta captura.

O padrão é compatível com conexão TCP seguida de encerramento abrupto. O número
22 costuma ser associado a SSH, mas esses pacotes não comprovam serviço, login,
autenticação ou comprometimento.

### Porta 23: reset como resposta ao SYN

| Pacote | Direção (ambos IPs 127.0.0.1) | Flags | SEQ absoluto | ACK absoluto |
| --- | --- | --- | --- | --- |
| 31 | 58118 → 23 | SYN | 1894079201 | 0 |
| 32 | 23 → 58118 | RST, ACK | 0 | 1894079202 |

A resposta inverte as portas e reconhece `1894079201 + 1`, sustentando a
classificação de padrão fechado no momento observado. Um PCAP isolado não permite
garantir se um reset foi gerado pelo host final ou por outro componente da rede.

## Validação e conclusões limitadas

Os números e campos foram comparados com TShark/Wireshark instalado no Windows.
O teste de comparação verifica todas as evidências das 1.000 tentativas e as
contagens dos 2.000 fluxos direcionais. O `capinfos` confirmou tamanho, hash,
quantidade de pacotes e duração. Consulte [validação](validacao.md).

Os endpoints loopback sustentam comunicação local ao ambiente de captura. O
modelo do equipamento e o sistema operacional de origem não são demonstrados
por esses campos: a atribuição ao Raspberry vem do contexto informado pelo usuário.
O nome do arquivo e os padrões não provam sozinhos o executável ou o comando Nmap.
Os comandos originais da varredura e da captura não foram recuperados nos
históricos consultados pelo usuário. O histórico salvo de `cyber` não apresentou
comandos correspondentes ao PCAP principal, e a consulta a `/root/.bash_history`
retornou arquivo inexistente. As transcrições foram fornecidas pelo usuário;
não houve acesso remoto direto nesta etapa. A técnica exata da varredura e a
interface original permanecem não confirmadas. Consulte o
[registro complementar](registro-experimento-01.md).

Não foram identificadas evidências de autenticação ou invasão por esta metodologia;
ela examina o estabelecimento TCP, sem analisar conteúdo de aplicações.

As tabelas deste documento derivam do arquivo real, não dos PCAPs sintéticos dos
testes. Os arquivos [resumo verificável](evidencias/experimento-01.json) e
[extração TShark](evidencias/tshark-portas-22-23.tsv) permitem conferir os campos.
