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
de bugs nem substituem um decodificador completo de protocolos. A versão não foi
executada no Kali/Raspberry nesta etapa. Em outra máquina, o PCAP real e o TShark
podem estar indisponíveis; o relatório de testes indica explicitamente os casos ignorados.
