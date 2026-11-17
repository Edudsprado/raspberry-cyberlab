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
anterior para o Raspberry e para a cópia no Windows. Esta etapa recalculou o hash
do arquivo do Windows; **não acessou novamente o Raspberry**.
O hash não autentica sozinho a origem da captura.

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
O comando original da varredura ainda deve ser incorporado ao registro experimental.

Não foram identificadas evidências de autenticação ou invasão por esta metodologia;
ela examina o estabelecimento TCP, sem analisar conteúdo de aplicações.

As tabelas deste documento derivam do arquivo real, não dos PCAPs sintéticos dos
testes. Os arquivos [resumo verificável](evidencias/experimento-01.json) e
[extração TShark](evidencias/tshark-portas-22-23.tsv) permitem conferir os campos.
