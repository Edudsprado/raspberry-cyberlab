# Raspberry CyberLab — Forensic Analyzer

Primeira ferramenta acadêmica do Raspberry CyberLab: análise **passiva e local**
de arquivos PCAP clássicos, com Python 3.10 ou superior e somente biblioteca padrão.
Versão 0.1.0. Entrega acadêmica prevista para **24/11/2026**.

Repositório: [Edudsprado/raspberry-cyberlab](https://github.com/Edudsprado/raspberry-cyberlab).

O analisador calcula SHA-256 dos bytes lidos, resume TCP por IP/porta e correlaciona
SYN, SYN/ACK, ACK e RST/ACK pela direção, números de sequência e confirmação.
Gera JSON e três CSVs, preservando o PCAP original.

## Primeiro passo: executar no Windows

Abra o PowerShell na pasta deste projeto. Não precisa instalar pacotes Python.

```powershell
Set-Location "$HOME\OneDrive\Imagens\Documentos\ChatGPT\Cyber"
python --version
python -m cyberlab "$HOME\Downloads\experimento-nmap.pcap" --output-dir relatorios-experimento-01 --expect-sha256 ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e
```

Se o comando `python` não estiver disponível, use `py -3` em seu lugar.
Esse hash é específico do experimento 01; para outro PCAP use seu próprio hash ou
omita `--expect-sha256`. Hash diferente interrompe a execução sem gerar relatórios.
Uma pasta que já contém relatórios é recusada: use outro nome para cada execução.

Saída validada com o arquivo real em 17/11/2026:

```text
CyberLab 0.1.0 | 2002 pacotes | 2002 TCP
SHA-256: ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e
Tentativas: {"aberta": 1, "fechada": 999}
Pacotes ignorados: 0
```

## Segundo passo: conferir os relatórios

Na pasta de saída:

| Arquivo | Conteúdo |
| --- | --- |
| `relatorio.json` | Hash, metadados, contagens, limitações, portas, tentativas e evidências numeradas |
| `portas.csv` | Resumo por IP/porta de destino, classificações e IDs das tentativas |
| `tentativas.csv` | Cliente/servidor, estado, ISNs e números dos pacotes SYN/SYNACK/ACK/RST |
| `fluxos-tcp.csv` | Cada direção IP:porta → IP:porta, contagens, bytes, flags e timestamps |

```powershell
Import-Csv .\relatorios-experimento-01\portas.csv | Where-Object { $_.server_port -in '22','23' } | Format-Table server_ip,server_port,classification,attempts
Get-FileHash "$HOME\Downloads\experimento-nmap.pcap" -Algorithm SHA256
python -m unittest discover -v
```

Os CSVs usam vírgula e UTF-8 com BOM. No Excel em português, se necessário importe
por **Dados → De Texto/CSV**, escolhendo vírgula como delimitador.

## Execução no Kali ou Raspberry Pi OS

Com Python 3.10+ instalado, copie o projeto e informe o caminho real do PCAP:

```bash
cd raspberry-cyberlab
python3 --version
python3 -m cyberlab "$HOME/Cyberlab/capturas/experimento-nmap.pcap" --output-dir relatorios-experimento-01
sha256sum "$HOME/Cyberlab/capturas/experimento-nmap.pcap"
python3 -m unittest discover -v
```

O caminho é um exemplo: na conversa anterior o nome no Raspberry foi digitado como
`expermiremnto-nmap.pcap`; confirme o nome existente com `ls` antes de executar.
Não precisa de root. A execução foi testada no Windows; Kali/Raspberry ainda não
foram executados nesta etapa.

Para incluir o teste de regressão do **PCAP real** fora de Downloads:

```bash
CYBERLAB_TEST_PCAP=/caminho/experimento-nmap.pcap python3 -m unittest discover -v
```

No PowerShell, use `$env:CYBERLAB_TEST_PCAP = 'C:\caminho\experimento-nmap.pcap'`.
Se o arquivo não estiver disponível, os testes reais são explicitamente ignorados;
os testes sintéticos continuam. Se TShark estiver disponível, o teste real também
compara todas as evidências e contagens por fluxo com sua decodificação independente.
É possível indicar seu executável pela variável `CYBERLAB_TSHARK`.

## Critérios de interpretação

| Estado da tentativa | Evidência exigida |
| --- | --- |
| `aberta` | SYN → SYN/ACK → ACK, mesma tupla invertida na resposta e SEQ/ACK compatíveis |
| `fechada` | SYN → RST/ACK do destino, reconhecendo o SYN, antes de qualquer SYN/ACK |
| `sem_resposta` | SYN sem resposta correlacionável; não significa filtrada ou fechada |
| `synack_sem_ack` | SYN/SYNACK observado, sem completar o handshake na captura |
| `reset_apos_synack` | Reset do destino após SYN/ACK; não classificado como fechada |
| `resposta_ambigua` | ISNs conflitantes do servidor ou origem/destino indistinguíveis |
| `abertura_simultanea` | SYNs nos dois sentidos, fora do classificador desta versão |
| `nao_suportado_syn_com_dados` | Dados em SYN/SYNACK, fora do classificador desta versão |

A janela padrão é **60 segundos desde o primeiro SYN**, configurável com
`--window-seconds`. Retransmissões de SYN com o mesmo ISN em uma tentativa pendente
são agrupadas. Um novo ISN substitui a tentativa ativa daquela tupla; a anterior
permanece no relatório. Depois de uma tentativa concluída, um novo SYN inicia outra
tentativa, inclusive com ISN repetido. Duplicatas completas não são removidas.

O resumo de porta apresenta `aberta` ou `fechada` quando há pelo menos uma tentativa
confirmada desse tipo; `mista` se ambos ocorrerem e `inconclusiva` se nenhum ocorrer.
Consulte sempre `statuses` e os IDs: um resumo confirmado pode coexistir com
tentativas inconclusivas. Nenhuma classificação implica estado atual do equipamento.

## Escopo e limites

- PCAP clássico 2.4, little/big endian, resolução de microssegundos ou nanossegundos.
- TCP/IPv4 em Ethernet (incluindo VLAN), RAW, NULL/LOOP, Linux SLL/SLL2 ou LINKTYPE_IPV4.
- IPv6, UDP, ARP, fragmentos IP e cabeçalhos incompletos são contabilizados como
  ignorados, com motivo. Não há remontagem nem validação de checksum.
- PCAPNG e enlaces não suportados são recusados. Para converter uma **cópia**:
  `editcap -F pcap entrada.pcapng convertido.pcap`. A conversão muda os bytes e o
  hash; preserve o original e registre ambos. Múltiplas interfaces podem exigir
  separação antes da conversão.
- Segue a ordem do arquivo; não reordena timestamps. Captura parcial, perda,
  reuso de tuplas, espelhamento e respostas forjadas limitam a interpretação.
- Todos os timestamps de relatório são UTC ou nanossegundos desde Unix epoch.
  Timestamps não são arredondados para `float`.
- Contagens por fluxo incluem todos os TCP/IPv4 decodificáveis, mesmo sem SYN.
  `captured_bytes` inclui enlace; `tcp_payload_bytes` conta dados TCP observados,
  incluindo retransmissões. Registros acima de 16 MiB são recusados.
- A leitura é incremental; fluxos, tentativas e evidências ficam em memória.
  Esta primeira versão prioriza capturas pequenas de laboratório.
- Um RST posterior ao handshake não altera uma tentativa já aberta. Em
  `unmatched_syn_rst_packets`, esse RST pode aparecer como controle não correlacionado;
  isso não significa pacote inválido ou ataque.
- SHA-256 identifica o conteúdo analisado. Não prova sozinho origem, autenticidade,
  integridade anterior à coleta ou cadeia de custódia. A ferramenta verifica mudanças
  comuns do arquivo durante a leitura, mas não substitui aquisição forense controlada.

## Documentação e GitHub

- [Análise real do experimento 01](docs/analise-forense.md)
- [Metodologia e formato dos dados](docs/metodologia.md)
- [Validação executada](docs/validacao.md)
- [Passos para GitHub](docs/github.md)
- [Roteiro até 24/11](docs/roteiro-academico.md)

O PCAP e os relatórios completos ficam fora do Git por padrão. A pasta `docs/evidencias`
contém apenas um resumo verificável e a extração textual das portas 22/23 para este
experimento de loopback.
