# Roteiro de apresentação — Raspberry CyberLab

Estrutura sugerida: seis slides, aproximadamente 6–8 minutos. Este arquivo é um
roteiro de conteúdo; não substitui um arquivo de slides. Preencher autoria e
identificação acadêmica antes da entrega.

## Slide 1 — Problema e objetivo

**Título:** Raspberry CyberLab — análise forense de tráfego TCP.

- Como distinguir uma conexão TCP estabelecida de uma tentativa recusada?
- Desenvolver um analisador Python para PCAPs locais.
- Produzir resultados verificáveis em CSV e JSON.

**Fala sugerida:** apresentar a pergunta e o objetivo do trabalho. Explicar que
a análise é passiva e usa uma captura já existente.

## Slide 2 — Ambiente e evidência

- Raspberry Pi 3 Model B Rev 1.2; Debian 13; Python 3.13.5, conforme coleta complementar.
- Desenvolvimento e comparação independente no Windows.
- PCAP com 160.208 bytes e 2.002 pacotes TCP/IPv4.
- SHA-256 coincidente entre o arquivo do Raspberry e a cópia do Windows.

**Fala sugerida:** distinguir os dados atuais do ambiente dos registros da
captura. Mostrar o hash sem afirmar que ele, sozinho, comprova a origem.

## Slide 3 — Como o analisador decide

- Aberta: SYN → SYN/ACK → ACK.
- Fechada: SYN → RST/ACK do destino.
- Correlacionar IPs, portas e SEQ/ACK; registrar os números dos pacotes.
- Resposta ausente ou handshake incompleto: manter classificação inconclusiva.

**Fala sugerida:** explicar o reconhecimento dos SYNs com o valor da sequência
mais um. Um reset posterior não desfaz um handshake completo já observado.

## Slide 4 — Resultados reais

| Porta | Evidência | Resultado |
| --- | --- | --- |
| 22/TCP | Pacotes 19 → 20 → 21 | Aberta |
| 23/TCP | Pacotes 31 → 32 | Fechada |

- 1.000 tentativas: 1 aberta e 999 fechadas.
- Nenhum pacote ignorado na captura estudada.
- Endpoints em 127.0.0.1.

**Fala sugerida:** mostrar no Wireshark os pacotes indicados. Explicar que
esses dados não comprovam autenticação SSH ou invasão.

## Slide 5 — Demonstração e validação

- Windows: 21 testes aprovados, incluindo comparação com TShark.
- Raspberry: 20 aprovados e 1 ignorado por ausência do TShark.
- Três CSVs idênticos byte por byte entre as duas execuções.
- JSON difere apenas no horário de análise e no nome de entrada.

**Demonstração no Raspberry:** entrar na pasta do projeto e escolher uma pasta
de saída ainda inexistente. O exemplo abaixo usa uma execução separada dos
relatórios de validação:

```bash
python3 -m cyberlab /home/cyber/Cyberlab/capturas/expermiremnto-nmap.pcap --output-dir relatorios-apresentacao-01 --expect-sha256 ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e
```

Mostrar a contagem final e as linhas das portas 22/23. Em novo ensaio, escolher
outro nome de saída. Conservar os relatórios anteriores.

## Slide 6 — Conclusão e limites

- O analisador reproduziu as classificações nos dois ambientes documentados.
- Os comandos originais da varredura e da captura não foram recuperados.
- Escopo atual: PCAP clássico e TCP/IPv4, sem remontagem ou análise de aplicação.
- Próximos passos: mais capturas de teste, registro experimental completo,
  suporte a IPv6 e PCAPNG.

**Encerramento sugerido:** apontar o código-fonte e os registros de validação.
Conferir se o link para o repositório público está correto no material da entrega.

## Antes da apresentação

- Preencher identificação acadêmica e verificar exigências de entrega.
- Ensaiar o comando em uma pasta de saída nova.
- Guardar código, PCAP original e relatórios para acesso offline.
- Preparar Wireshark com filtros `tcp.port == 22` e `tcp.port == 23`.
- Não executar uma nova varredura como se ela recriasse a evidência original.
