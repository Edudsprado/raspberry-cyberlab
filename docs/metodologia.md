# Metodologia — versão 0.1.0

1. Abrir o arquivo em modo binário somente para leitura e validar o cabeçalho PCAP.
2. Atualizar SHA-256 com os mesmos bytes usados na análise, incluindo cabeçalhos.
3. Ler registros completos, validar comprimentos e preservar numeração original
   iniciada em 1. PCAP estruturalmente truncado interrompe a análise.
4. Decodificar enlace, IPv4 e TCP. Pacotes não suportados ou inválidos não são
   classificados; aparecem em `capture.skipped_reasons`.
5. Resumir fluxos direcionais pela tupla `(IP origem, porta origem, IP destino, porta destino)`.
6. Iniciar tentativa em SYN sem ACK/RST/FIN e sem dados. Flags ECN são aceitas.
7. Correlacionar resposta na tupla inversa, dentro da janela temporal e reconhecendo
   `ISN_cliente + 1`, com aritmética módulo 2³².
8. Em SYN/ACK, guardar `ISN_servidor`. Em ACK final, exigir direção cliente → servidor,
   `SEQ = ISN_cliente + 1`, `ACK = ISN_servidor + 1`, sem SYN/RST/FIN, posterior ao
   SYN/ACK em ordem de arquivo e com timestamp não anterior à última evidência.
9. Em RST/ACK diretamente após SYN, registrar padrão fechado. Reset após SYN/ACK
   recebe estado próprio. Reset após handshake completo não desfaz evidência de abertura.
10. Comparar o hash esperado, se fornecido, e só então gravar JSON/CSV. Arquivos
    de saída existentes não são sobrescritos. Erros retornam código 1.

Esta é uma correlação conservadora de handshakes, não uma implementação completa
da máquina de estados TCP, detector de Nmap, ferramenta de invasão ou autenticação
de serviços. Não conclui que porta 22 necessariamente executava SSH; o número de
porta é compatível com a convenção desse serviço. O comando original do scanner
deve ser documentado separadamente para confirmar a técnica utilizada.

## JSON e rastreabilidade

`schema_version: "1.0"` identifica a estrutura. `analyzer_version` identifica o
programa. `source` contém nome base, tamanho, formato e SHA-256, sem o caminho
completo da máquina. `analyzed_at_utc` é a hora da execução, distinta da hora dos
pacotes. A data de execução muda em novas análises; as evidências do mesmo PCAP
permanecem reproduzíveis com os mesmos parâmetros.

`capture.packets = capture.tcp_packets + capture.skipped_packets`.
`status_counts` conta tentativas, não pacotes. `ports` agrupa tentativas por IP/porta
de destino. `tcp_flows` agrupa todos os pacotes TCP/IPv4 aceitos, em cada direção.

Cada tentativa tem ID, endpoints, ISNs, números de pacotes e `evidence`, com flags,
SEQ/ACK absolutos e timestamp exato. O Wireshark pode mostrar sequências relativas;
para comparar, desative essa opção ou use `tcp.seq_raw` e `tcp.ack_raw` no TShark.
As evidências listam a sequência usada para classificar; não incluem todo o tráfego
posterior. Para revisar o encerramento, consulte o PCAP e o resumo de fluxos.

## Referências primárias

- [RFC 9293 — TCP, handshake e processamento de resets](https://www.rfc-editor.org/rfc/rfc9293.html).
- [IETF — formato PCAP, draft-ietf-opsawg-pcap-09](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/09/).
  É um Internet-Draft, não uma RFC publicada.
- [IETF — tipos de enlace PCAP, draft-ietf-opsawg-pcaplinktype-18](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcaplinktype-18).

O código implementa um subconjunto explícito desses formatos; consulte as
limitações no README antes de interpretar resultados de outras capturas.
