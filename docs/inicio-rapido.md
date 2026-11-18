# CyberLab Forensic Analyzer — começar aqui

Versão 0.1.0, conferida no Windows em 18/11/2026. Entrega prevista: 24/11/2026.
Python 3.10 ou superior, sem instalar pacotes. A ferramenta lê uma captura local,
resume fluxos e flags TCP, calcula SHA-256 e grava JSON/CSV.

## Etapa 1 — executar no notebook

Abra o PowerShell na pasta que contém `cyberlab` e `tests`. Se estiver usando o
ZIP, extraia-o primeiro e abra o PowerShell dentro da pasta extraída.

Execute somente este comando por enquanto:

```powershell
python -m cyberlab "$HOME\Downloads\experimento-nmap.pcap" --output-dir relatorios-minha-execucao --expect-sha256 ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e
```

Se `python` não for encontrado, substitua-o por `py -3`. Para outro PCAP, informe
seu caminho e seu próprio hash. O hash acima identifica apenas o experimento 01.
Se a pasta já contiver relatórios, escolha outro nome, como
`relatorios-minha-execucao-02`; os arquivos anteriores são preservados.

No experimento 01, a saída conferida nesta máquina foi:

```text
CyberLab 0.1.0 | 2002 pacotes | 2002 TCP
SHA-256: ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e
Tentativas: {"aberta": 1, "fechada": 999}
Pacotes ignorados: 0
```

Pare aqui para conferir a saída antes da próxima etapa. Se ocorrer erro,
conserve a mensagem para diagnóstico.

## Etapa 2 — conferir as duas portas

Depois de confirmar a execução, use:

```powershell
Import-Csv .\relatorios-minha-execucao\portas.csv | Where-Object { $_.server_port -in '22','23' } | Format-Table server_ip,server_port,classification,attempts
```

O resultado do PCAP do experimento é `127.0.0.1:22` aberta e `127.0.0.1:23`
fechada, uma tentativa para cada uma. O arquivo completo contém 1.000 portas.

| Arquivo gerado | Para que serve |
| --- | --- |
| `relatorio.json` | SHA-256, metadados, contagens, tentativas e evidências numeradas |
| `portas.csv` | Resumo das portas e classificações |
| `tentativas.csv` | Pacotes SYN, SYN/ACK, ACK e RST usados na correlação |
| `fluxos-tcp.csv` | IPs/portas por direção, pacotes, bytes e combinações de flags |

Os CSVs usam vírgula. Para abrir no Excel, use **Dados → De Texto/CSV** se as
colunas não forem separadas automaticamente.

## Etapa 3 — repetir os testes, quando necessário

Não é preciso digitar cada teste. Na pasta do projeto, execute um único comando
no PowerShell do Windows:

```powershell
.\testar.cmd
```

No Raspberry/Linux:

```bash
sh testar.sh
```

O script localiza o Python, executa a suite inteira e salva `testes.log` e
`resultado.json` em uma pasta nova dentro de `relatorios-testes`. Mostra no final
quantos testes passaram, foram ignorados ou falharam. Não instala programas,
não captura tráfego e não envia arquivos. O código de saída é 0 quando não há
falhas, inclusive se houver casos ignorados; nesse caso aparece explicitamente
`OK COM TESTES IGNORADOS`. Código 1 indica falha nos testes; argumento inválido
retorna código 2.

Ele procura o PCAP em Downloads ou nos dois nomes já registrados dentro de
`~/Cyberlab/capturas`. Também aceita `CYBERLAB_TEST_PCAP`. Para informar outra
localização do **mesmo experimento 01**, passe o caminho entre aspas:

```bash
sh testar.sh "/home/cyber/Cyberlab/capturas/expermiremnto-nmap.pcap"
```

No Windows, use `.\testar.cmd "C:\caminho\experimento-nmap.pcap"`.
Se um caminho informado não existir, o script interrompe com uma mensagem de
erro. Os testes reais conferem o hash conhecido do experimento 01; outro PCAP
exige seus próprios critérios de teste. Para analisar outras capturas, use o
comando do analisador descrito na Etapa 1, com seu próprio hash.

Os testes sintéticos são exemplos criados para verificar o programa; não são
evidências da captura real. Os testes do experimento usam o PCAP em Downloads.
Sem esse arquivo ou sem TShark, os casos correspondentes aparecem como ignorados.
O programa funciona sem TShark; ele só é usado para comparação independente.

No Windows, o atalho teve 21 testes aprovados. No Raspberry, a execução
compartilhada pelo usuário teve 20 aprovados e 1 ignorado por falta do TShark.
Veja os
[casos verificados dos atalhos](testes-automatizados.md).

No Raspberry ou Linux, use `python3` e informe o caminho real do PCAP.
A execução desta retomada foi feita no Windows; não foi realizado teste remoto.

## Como interpretar

- `aberta`: SYN → SYN/ACK → ACK, com IPs, portas e SEQ/ACK compatíveis.
- `fechada`: SYN → RST/ACK do destino, reconhecendo o SYN.
- SYN sem resposta ou SYN/ACK sem ACK final: evidência incompleta, mantida como
  inconclusiva no resumo de porta.
- Um reset após o handshake não desfaz a evidência de abertura.

Esses estados descrevem o padrão da captura, sem garantir o estado atual ou o
serviço executado. A versão lê PCAP clássico e TCP/IPv4; não lê PCAPNG/IPv6 e
não remonta fragmentos. SHA-256 identifica os bytes; sozinho não prova origem.
Mais detalhes em [metodologia](metodologia.md) e [validação desta versão](validacao-2026-11-18.md).

## Até a entrega

Primeiro reproduza a execução e confira as portas. Depois prepare a demonstração
com esses relatórios, mantendo os comandos originais de captura como pendentes
se não houver registros. Reserve 23/11 para ensaio e cópia offline; entrega em
24/11/2026. A documentação contém instruções para as etapas seguintes, sem exigir
que todas sejam feitas agora.

O pacote de entrega contém código, testes e documentação. Capturas e relatórios
completos ficam separados e locais. Revise o conteúdo antes de compartilhar;
relatórios podem conter endereços e horários da rede. Nesta retomada não houve
publicação nem envio de tráfego da faculdade.
