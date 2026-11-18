# Validação executada

Execução local no Windows em **17/11/2026**, com Python 3.12.3.

- **21 testes aprovados**, sem testes ignorados nesta máquina.
- 18 testes com capturas sintéticas para casos de protocolo, integridade e exportação.
- 3 testes sobre `experimento-nmap.pcap`: totais/hash; portas 22/23;
  comparação independente com TShark de todas as evidências e fluxos.
- CLI executada com `--expect-sha256`; JSON e três CSVs gerados em `relatorios-real`.
- `capinfos` confirmou 2.002 pacotes, 160.208 bytes, duração de 0,086611 s e o SHA-256.
- SHA-256 do PCAP conferido novamente após a validação.

O [log dos testes](evidencias/unittest-windows.txt) registra a execução efetiva.
O [registro da verificação](evidencias/verificacao-windows.json) inclui versões,
saída do capinfos e os hashes medidos antes/depois da validação.

## Reproduzir

Na raiz do projeto:

```powershell
python -m unittest discover -v
python -m cyberlab "$HOME\Downloads\experimento-nmap.pcap" --output-dir relatorios-validacao --expect-sha256 ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e
& 'C:\Program Files\Wireshark\capinfos.exe' "$HOME\Downloads\experimento-nmap.pcap"
& 'C:\Program Files\Wireshark\tshark.exe' -n -r "$HOME\Downloads\experimento-nmap.pcap" -Y 'tcp.port == 22 || tcp.port == 23' -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags -e tcp.seq_raw -e tcp.ack_raw
```

As fixtures cobrem handshake completo, reset do cliente após abertura, porta fechada,
ACK/tupla incorretos, SYN/ACK sem ACK final, captura sem SYN, retransmissões, reuso de
portas, respostas ambíguas, wraparound de sequência, ECN, Fast Open recusado,
abertura simultânea, janela temporal e regressões de timestamp. Também verificam
as quatro variantes de magic PCAP, enlaces implementados, VLAN, pacotes fragmentados
ou inválidos, PCAPNG recusado, arquivo truncado, hash incorreto, captura vazia,
CSV/JSON e recusa de sobrescrita.

Os testes sintéticos exercitam os casos previstos; não constituem prova de ausência
de bugs nem substituem um decodificador completo de protocolos. Kali não foi
executado nesta etapa. Em outra máquina, o PCAP real e o TShark
podem estar indisponíveis; o relatório de testes indica explicitamente os casos ignorados.

## Validação no Raspberry — transcrição fornecida pelo usuário

Ambiente informado: Raspberry Pi 3 Model B Rev 1.2, Debian GNU/Linux 13 (trixie),
kernel `6.18.50+rpt-rpi-v8`, Python 3.13.5.

O pacote `cyberlab-analyzer-0.1.0.zip` foi preparado no Windows. Seu SHA-256
calculado localmente foi `f62467262628ea4434f8befd02b7951e69a056439a0eadce6472ce5112814ecc`.
O usuário forneceu a saída do SCP concluído e do `sha256sum` no Raspberry com o
mesmo valor, além da extração sem erro apresentado.

No diretório `/home/cyber/Cyberlab/cyberlab-analyzer-0.1.0`, foi informado o comando:

```bash
CYBERLAB_TEST_PCAP=/home/cyber/Cyberlab/capturas/expermiremnto-nmap.pcap python3 -m unittest discover -v
```

Resultado transcrito: **21 testes descobertos, 20 aprovados, 1 ignorado**,
em **0,518 s**, com `OK (skipped=1)`. Os 18 testes sintéticos e os 2 testes de
regressão do PCAP real passaram. O teste de comparação com TShark foi ignorado
com o motivo `TShark indisponível para comparação independente`.

O [log transcrito](evidencias/unittest-raspberry-transcrito.txt) conserva a saída
de testes fornecida pelo usuário. Não houve acesso remoto direto nesta validação.

### Geração de relatórios no Raspberry

O usuário forneceu posteriormente a execução, na mesma pasta do projeto:

```bash
python3 -m cyberlab /home/cyber/Cyberlab/capturas/expermiremnto-nmap.pcap --output-dir relatorios-raspberry-01 --expect-sha256 ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e
```

A saída informa 2.002 pacotes, todos TCP; 1 tentativa aberta e 999 fechadas;
nenhum pacote ignorado e o SHA-256 esperado. O programa informou a geração de
`relatorio.json`, `portas.csv`, `tentativas.csv` e `fluxos-tcp.csv` na pasta
`relatorios-raspberry-01`. Os totais coincidem com a execução direta no Windows.

O [log transcrito da execução](evidencias/cli-raspberry-transcrito.txt) preserva
a saída fornecida pelo usuário. Os quatro arquivos gerados no Raspberry foram
posteriormente recebidos no Windows e comparados diretamente, conforme a seção abaixo.

O usuário também forneceu as linhas das portas 22/23 no `portas.csv` do
Raspberry: `127.0.0.1:22` aberta, uma tentativa com ID 10;
`127.0.0.1:23` fechada, uma tentativa com ID 15. Os valores coincidem com a
execução no Windows; veja a [seleção transcrita](evidencias/portas-raspberry-transcrito.txt).

## Comparação direta dos relatórios recebidos

Foram recebidos `relatorio.json`, `portas.csv`, `tentativas.csv` e `fluxos-tcp.csv`
na pasta local `relatorios-raspberry-recebidos`. A comparação com os relatórios
de `relatorios-validacao`, gerados diretamente no Windows, confirmou:

| Arquivo | Resultado da comparação |
| --- | --- |
| portas.csv | 1.000 linhas de dados; idêntico byte por byte |
| tentativas.csv | 1.000 linhas de dados; idêntico byte por byte |
| fluxos-tcp.csv | 2.000 linhas de dados; idêntico byte por byte |
| relatorio.json | Todos os campos iguais, exceto analyzed_at_utc e source.name |

O JSON do Windows identifica `experimento-nmap.pcap` e horário de análise
`2026-11-17T15:27:06.685762+00:00`; o recebido do Raspberry identifica
`expermiremnto-nmap.pcap` e `2026-11-17T16:06:16.800098+00:00`. Essas diferenças
explicam por que os hashes dos JSONs são distintos. As evidências, timestamps
dos pacotes, parâmetros, fluxos, tentativas e classificações são iguais.

O [registro estruturado da comparação](evidencias/comparacao-windows-raspberry.json)
contém hashes e tamanhos dos oito arquivos comparados, as duas diferenças no JSON
e os resultados da conferência de todas as linhas dos CSVs. Essa comparação foi
realizada diretamente nesta máquina; a identificação do ambiente remoto e sua
execução continuam fundamentadas nas transcrições fornecidas pelo usuário.
