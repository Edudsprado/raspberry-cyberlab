# Raspberry CyberLab: desenvolvimento e validação de um analisador forense de tráfego TCP

| Campo | Informação |
| --- | --- |
| Autor(es) | A preencher |
| Instituição | A preencher |
| Curso e disciplina | A preencher |
| Professor(a) | A preencher |
| Entrega prevista | 24 de novembro de 2026 |
| Versão do software | CyberLab Forensic Analyzer 0.1.0 |

## Resumo

Este trabalho apresenta o desenvolvimento do CyberLab Forensic Analyzer, uma
ferramenta em Python para análise passiva de arquivos PCAP locais. O objetivo é
identificar padrões de estabelecimento e recusa de conexões TCP, resumir fluxos
por IP e porta, calcular SHA-256 e exportar resultados em CSV e JSON. A avaliação
utilizou uma captura de 160.208 bytes e 2.002 pacotes TCP/IPv4. Foram identificadas
1.000 tentativas, sendo uma com handshake completo na porta 22 e 999 com resposta
compatível com porta fechada, incluindo a porta 23. A validação no Windows contou
com 21 testes aprovados e comparação independente com TShark. No Raspberry Pi 3,
as saídas fornecidas pelo usuário registraram 20 testes aprovados e um ignorado
por falta do TShark. A inspeção direta dos relatórios recebidos do Raspberry
confirmou três CSVs idênticos aos do Windows e diferenças no JSON restritas ao
horário da análise e ao nome do arquivo de entrada. O estudo também documenta
limites de atribuição, captura incompleta e ausência dos comandos originais.

**Palavras-chave:** análise de tráfego; TCP; PCAP; Python; forense digital; Raspberry Pi.

## 1. Introdução

A análise de tráfego permite examinar como sistemas tentam estabelecer conexões
e como os destinos respondem. Em um laboratório acadêmico, a interpretação dos
cabeçalhos TCP pode apoiar o estudo de reconhecimento de portas e de evidências
de rede, desde que as conclusões permaneçam limitadas ao conteúdo observado.

O Raspberry CyberLab reúne uma captura local, inspeção com Wireshark/TShark e
desenvolvimento de software próprio. A pergunta investigada é: como distinguir,
de forma reproduzível, tentativas com handshake TCP completo de tentativas
respondidas com reset, preservando a rastreabilidade dos pacotes utilizados?

## 2. Objetivos

O objetivo geral é desenvolver e validar um analisador de capturas locais que
relacione evidências TCP a padrões de abertura ou recusa de conexões.

Os objetivos específicos são:

- Ler PCAPs clássicos e resumir tráfego TCP/IPv4 por IP e porta.
- Correlacionar SYN, SYN/ACK, ACK e RST/ACK com validação de direção e SEQ/ACK.
- Calcular SHA-256 dos bytes analisados e produzir CSV e JSON.
- Registrar os números dos pacotes que sustentam cada classificação.
- Validar resultados com testes, TShark e execução em Windows e Raspberry.

## 3. Fundamentação

O TCP usa números de sequência e de confirmação para estabelecer e acompanhar
conexões. No handshake convencional, o iniciador envia SYN, o destino responde
com SYN/ACK e o iniciador confirma com ACK. Uma resposta RST/ACK diretamente ao
SYN é compatível com recusa da conexão. A interpretação exige considerar a
direção do tráfego e os números reconhecidos, conforme a especificação TCP [1].

O PCAP clássico organiza a captura em cabeçalho global e registros de pacotes
com timestamps e comprimentos [2]. O SHA-256 calculado sobre o arquivo permite
comparar seu conteúdo com outra cópia. Essa comparação não comprova, sozinha,
a origem da captura ou uma cadeia de custódia completa.

## 4. Materiais e metodologia

### 4.1. Ambiente e evidência

O desenvolvimento e a validação direta foram realizados no Windows com Python
3.12.3 e TShark/Wireshark 4.4.6. Na coleta complementar, o usuário informou os
seguintes dados do Raspberry por transcrições de terminal:

| Componente | Identificação informada |
| --- | --- |
| Equipamento | Raspberry Pi 3 Model B Rev 1.2 |
| Sistema | Debian GNU/Linux 13 (trixie), DEBIAN_VERSION_FULL=13.7 |
| Kernel | 6.18.50+rpt-rpi-v8 |
| Python | 3.13.5 |
| Nmap | 7.95, plataforma aarch64-unknown-linux-gnu |
| tcpdump / libpcap | 4.99.5 / 1.10.5 |

Esses valores descrevem o ambiente consultado posteriormente; as versões no
momento da captura original não foram confirmadas.

A evidência analisada no Windows chama-se `experimento-nmap.pcap`. A saída de
hash fornecida para o Raspberry identifica a grafia `expermiremnto-nmap.pcap`.
O SHA-256 coincide nas duas verificações:

```text
ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e
```

O arquivo tem 160.208 bytes, contém 2.002 pacotes e usa PCAP clássico com enlace
Ethernet e resolução de microssegundos. Os timestamps extremos são
17/11/2026 13:50:50.902836 UTC e 13:50:50.989447 UTC, com intervalo de 0,086611 s.
Não foi verificada a sincronização do relógio da captura.

### 4.2. Implementação

O analisador usa somente a biblioteca padrão do Python. A leitura é incremental,
com validação dos comprimentos dos registros e dos cabeçalhos. Pacotes fora do
escopo são contabilizados como ignorados, com motivo. PCAPs estruturalmente
inválidos são recusados.

Cada tentativa é correlacionada pela tupla de IPs e portas. A resposta deve ter
a direção inversa e reconhecer o SYN. Para classificar uma tentativa como aberta,
é necessário observar SYN, SYN/ACK e ACK compatíveis, dentro da janela padrão de
60 segundos desde o SYN. Aritmética módulo 2³² trata os números de sequência.

Uma resposta RST/ACK diretamente ao SYN sustenta o padrão fechado. SYN sem
resposta e SYN/ACK sem confirmação final recebem estados inconclusivos. Um reset
posterior ao handshake não altera a classificação de abertura já observada.

O programa gera `relatorio.json`, `portas.csv`, `tentativas.csv` e
`fluxos-tcp.csv`. O JSON conserva metadados, limitações e evidências com números
de pacote. Arquivos de saída existentes não são sobrescritos.

### 4.3. Validação

Os testes sintéticos cobrem sequências completas, respostas incorretas,
retransmissões, reuso de portas, estados inconclusivos, comprimentos inválidos,
variantes PCAP, exportação e verificação de hash. Dois testes de regressão
verificam o PCAP real; um terceiro compara todas as evidências classificadas e
contagens de fluxos com a decodificação independente do TShark.

Um pacote do projeto foi transferido ao Raspberry, com hash conferido pelo
usuário. As saídas de execução remota foram recebidas por transcrição. Depois,
os quatro relatórios foram transferidos ao Windows e comparados diretamente
com os arquivos produzidos localmente. Assim, distinguem-se informações
fornecidas pelo usuário de verificações feitas diretamente sobre os arquivos.

## 5. Resultados

Todos os 2.002 pacotes foram decodificados como TCP/IPv4. Não houve pacotes
ignorados, registros truncados ou regressões de timestamp nesta captura.
Foram resumidos 2.000 fluxos direcionais e identificadas 1.000 tentativas para
1.000 portas de destino distintas: uma aberta e 999 fechadas.

| Caso | Pacotes | Sequência | Classificação |
| --- | --- | --- | --- |
| 127.0.0.1:22, tentativa 10 | 19, 20 e 21 | SYN → SYN/ACK → ACK | Aberta |
| 127.0.0.1:23, tentativa 15 | 31 e 32 | SYN → RST/ACK | Fechada |

Na porta 22, o SYN tem SEQ 4173570263; o SYN/ACK reconhece 4173570264 e usa SEQ
3856505152; o ACK final reconhece 3856505153. O pacote 22 é um RST/ACK enviado
pelo iniciador após o handshake. Na porta 23, o SYN tem SEQ 1894079201 e o
RST/ACK reconhece 1894079202. Ambos os endpoints aparecem como `127.0.0.1`.

| Verificação | Windows | Raspberry |
| --- | --- | --- |
| Testes descobertos | 21 | 21 |
| Aprovados | 21 | 20 |
| Ignorados | 0 | 1, por ausência do TShark |
| Pacotes TCP na execução real | 2.002 | 2.002 |
| Tentativas abertas / fechadas | 1 / 999 | 1 / 999 |

Na comparação direta dos arquivos recebidos, `portas.csv` e `tentativas.csv`
têm 1.000 linhas de dados cada, e `fluxos-tcp.csv` tem 2.000. Os três CSVs são
idênticos byte por byte aos do Windows. No JSON, somente `analyzed_at_utc` e
`source.name` diferem. Todos os demais valores coincidem, incluindo as evidências
e timestamps dos pacotes [3].

## 6. Discussão e limitações

A concordância entre os relatórios e a comparação com TShark sustentam a
reprodutibilidade para este conjunto de dados e os casos cobertos pelos testes.
Não constituem garantia de correção para todo tráfego TCP possível.

Os IPs de loopback sustentam comunicação local ao ambiente de captura, mas os
campos do PCAP não comprovam isoladamente o equipamento de origem. A porta 22
é convencionalmente associada a SSH; o handshake analisado não comprova serviço,
autenticação, exploração ou comprometimento.

Os históricos consultados não recuperaram o comando Nmap nem o tcpdump que
gerou o PCAP principal. O histórico do usuário contém uma captura de outro
arquivo, `teste-inicial.pcap`, e o arquivo `/root/.bash_history` não foi encontrado.
Portanto, a técnica exata da varredura e a interface original permanecem não
confirmadas. Essa lacuna deve constar no trabalho, sem reconstrução de comandos
como se fossem fatos observados.

Esta versão analisa PCAP clássico e TCP/IPv4, sem remontagem de fragmentos,
validação de checksums ou inspeção de aplicação. IPv6 e PCAPNG estão fora do
escopo. Capturas incompletas, timestamps fora de ordem, respostas forjadas e
reuso de tuplas podem limitar a interpretação. Ausência de resposta não permite
concluir que uma porta esteja fechada ou filtrada.

## 7. Conclusão

O CyberLab Forensic Analyzer cumpriu os objetivos de analisar a captura local,
resumir fluxos TCP, calcular SHA-256, exportar relatórios e distinguir os padrões
definidos de conexão aberta e recusada. Na evidência estudada, a porta 22 teve
handshake completo e a porta 23 respondeu ao SYN com RST/ACK. Os relatórios
reproduziram os resultados entre Windows e Raspberry nos ambientes documentados.

Como continuidade, recomenda-se ampliar o conjunto de capturas de teste,
registrar os comandos e parâmetros desde o início dos próximos experimentos e
avaliar suporte a IPv6 e PCAPNG. A publicação deve preservar a separação entre
evidência original, dados derivados, transcrições e conclusões.

## Referências

[1] IETF. **RFC 9293: Transmission Control Protocol (TCP)**. 2022.
Disponível em: https://www.rfc-editor.org/rfc/rfc9293.html.

[2] HARRIS, G.; RICHARDSON, M. **PCAP Capture File Format**.
draft-ietf-opsawg-pcap-09, 2026. Internet-Draft.
Disponível em: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/09/.

[3] RASPBERRY CYBERLAB. **Registros de validação e comparação de relatórios**.
Resultados sintetizados no Apêndice A deste relatório. Logs e documentos
anteriores preservados em backup local, fora do conteúdo publicado.

**Código-fonte:** [Raspberry CyberLab](https://github.com/Edudsprado/raspberry-cyberlab).

## Apêndice A — Rastreabilidade e organização

### Origem dos registros

- Windows: leitura direta do PCAP, testes e comparação independente com TShark.
- Raspberry: identificação do ambiente, hash do PCAP e saídas de execução
  fornecidos pelo usuário por transcrição de terminal.
- Relatórios do Raspberry: quatro arquivos recebidos no Windows e inspecionados
  diretamente, preservando a distinção entre transcrições e arquivos recebidos.

O nome no Windows é `experimento-nmap.pcap`; o nome informado no Raspberry é
`/home/cyber/Cyberlab/capturas/expermiremnto-nmap.pcap`. Os hashes coincidem.
O arquivo `teste-inicial.pcap` tem outro hash e não foi usado para atribuir
comandos ou interface à captura principal.

### Comparação direta de arquivos

| CSV | Linhas de dados | SHA-256, coincidente entre Windows e arquivo recebido |
| --- | ---: | --- |
| portas.csv | 1.000 | 2764e677ae76846d1bb4dd2d3d48edc09a3938bdb8bf7f50148e677e6d0e3639 |
| tentativas.csv | 1.000 | 3bd5804b389a0f4e1cba843756f20705b1abd99c1effce1155908ae4048ad4c1 |
| fluxos-tcp.csv | 2.000 | 224b1452b816595634305e49d2f534962292e1d6a244da3efaac31d4944e3ae9 |

No JSON, somente `source.name` e `analyzed_at_utc` diferem. A execução Windows
registrou `2026-11-17T15:27:06.685762+00:00`; a execução Raspberry,
`2026-11-17T16:06:16.800098+00:00`. As evidências, parâmetros, contagens,
classificações e timestamps dos pacotes coincidem.

### Interpretação de estados

`sem_resposta` e `synack_sem_ack` preservam tentativas incompletas.
`reset_apos_synack`, `resposta_ambigua`, `abertura_simultanea` e
`nao_suportado_syn_com_dados` recebem tratamento separado do padrão aberto/fechado.
O resumo de uma porta é `mista` se houver tentativas abertas e fechadas e
`inconclusiva` quando não houver nenhuma tentativa confirmada desses dois tipos.

### Organização simplificada

A aplicação foi reunida em `analyzer.py`, na raiz do repositório, mantendo a
lógica de análise. Os testes continuam em `tests/test_analyzer.py`.
O README reúne a execução, os resultados e o roteiro da demonstração.
Não há arquivo de apresentação separado. Os documentos e logs anteriores foram
preservados em um backup local antes da reorganização.

A suíte de testes deve ser executada com `python -m unittest discover -v`
(ou `python3` no Raspberry). Para analisar uma captura, use `python analyzer.py`
seguido do caminho do PCAP e das opções documentadas no README.

### Verificação após a simplificação — 21/11/2026

A aplicação em arquivo único foi executada diretamente no Windows sobre o PCAP
real com o SHA-256 esperado. Os 21 testes passaram, incluindo a comparação
independente com TShark. Os três CSVs gerados foram idênticos byte por byte aos
relatórios Windows anteriores. Todos os valores do JSON coincidiram após excluir
somente `analyzed_at_utc`, que identifica uma nova execução.

A nova estrutura e o novo comando `python3 analyzer.py` ainda não foram
reexecutados no Raspberry. A validação anterior nesse equipamento refere-se à
estrutura distribuída naquele momento, com a mesma lógica de análise.
