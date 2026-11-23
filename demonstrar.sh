#!/bin/sh
# Analisa a captura Wi-Fi de 23/11/2026; testes usam o PCAP original.
set -eu

usage() {
    cat <<'HELP'
Uso: sh demonstrar.sh [PCAP-da-execucao-Wi-Fi] [opcoes]

  --ip IP          IP de destino; use todos para incluir o Raspberry
  --porta PORTA    Mostrar somente essa porta de destino
  --estado ESTADO  aberta, fechada, inconclusiva, mista ou todos
  --ajuda          Mostrar esta ajuda

Sem opcoes: mostra as portas abertas do notebook 10.159.233.136.
Os filtros afetam somente a tabela; os relatorios permanecem completos.
Analisa a captura Wi-Fi de 23/11/2026, com hash fixo. Nao faz varredura.
O argumento PCAP permite indicar outra copia da mesma captura.
Os testes de regressao usam separadamente o PCAP original de loopback.
Titulos coloridos em terminais compativeis. Desativar: CYBERLAB_COLOR=0.
HELP
}

pcap="$HOME/Cyberlab/capturas/wlan.oEVHg4/captura.pcap"
test_pcap="$HOME/Cyberlab/capturas/expermiremnto-nmap.pcap"
custom_pcap=0
filter_ip='10.159.233.136'
filter_port=''
filter_state='aberta'
while [ "$#" -gt 0 ]; do
    case "$1" in
        --ajuda|-h|--help) usage; exit 0 ;;
        --ip|--porta|--estado)
            option=$1
            if [ "$#" -lt 2 ]; then
                printf 'Falta o valor de %s.\n' "$option" >&2
                exit 2
            fi
            case "$option" in
                --ip) filter_ip=$2 ;;
                --porta) filter_port=$2 ;;
                --estado) filter_state=$2 ;;
            esac
            shift 2 ;;
        -*) printf 'Opcao desconhecida: %s\n' "$1" >&2; exit 2 ;;
        *)
            if [ "$custom_pcap" -eq 1 ]; then usage >&2; exit 2; fi
            pcap=$1
            custom_pcap=1
            shift ;;
    esac
done

python3 - "$filter_ip" "$filter_port" "$filter_state" <<'VALIDATE'
import ipaddress
import sys
ip, port, state = sys.argv[1:]
try:
    if ip and ip != "todos":
        ipaddress.IPv4Address(ip)
    if port and (not port.isascii() or not port.isdecimal() or not 0 <= int(port) <= 65535):
        raise ValueError("porta deve ser um numero entre 0 e 65535")
    if state not in ("", "aberta", "fechada", "inconclusiva", "mista", "todos"):
        raise ValueError("estado deve ser aberta, fechada, inconclusiva, mista ou todos")
except ValueError as error:
    sys.exit(f"Filtro invalido: {error}")
VALIDATE

color=''
reset=''
if [ "${CYBERLAB_COLOR:-1}" = 1 ] && [ -t 1 ] && [ -z "${NO_COLOR+x}" ] && [ "${TERM:-dumb}" != dumb ]; then
    color=$(printf '\033[1;36m')
    reset=$(printf '\033[0m')
fi
section() { printf '\n%s%s%s\n' "$color" "$1" "$reset"; }
case "$pcap" in
    /*) ;;
    *) pcap="$PWD/$pcap" ;;
esac

if [ ! -f "$pcap" ]; then
    printf 'PCAP nao encontrado: %s\n' "$pcap" >&2
    exit 2
fi

project_dir=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
cd "$project_dir"
out=$(mktemp -d "$project_dir/relatorios-demonstracao.XXXXXX")
expected_sha256=d62419d0019a9ebf0ac28e2935c3e053cc92db01c5e03681c4541f48cbe13139

section '============================================================'
printf '%s\n' '  RASPBERRY CYBERLAB - Forensic Analyzer 0.1.0' '  Experimento Wi-Fi - 23/11/2026'
printf '  PCAP: %s\n' "$pcap"
printf '  Rede registrada: 10.159.233.0/24 - Interface: wlan0\n'
printf '  Raspberry: 10.159.233.58 - Notebook: 10.159.233.136\n'
printf '  O resumo global inclui as duas direcoes da captura.\n'
section '============================================================'
section 'ETAPA 1 DE 3 - Testes de regressao - captura original de loopback'
printf '  PCAP dos testes: %s\n' "$test_pcap"
if CYBERLAB_TEST_PCAP="$test_pcap" python3 -m unittest discover -v >"$out/testes.log" 2>&1; then
    python3 - "$out/testes.log" <<'TESTS'
import pathlib
import re
import sys
log = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
summary = re.search(r"^Ran (\d+) tests? in (.+)$", log, re.MULTILINE)
skips = re.findall(r"^.*? \.\.\. skipped (.+)$", log, re.MULTILINE)
if summary:
    total = int(summary[1])
    print(f"  Aprovados: {total - len(skips)} - Ignorados: {len(skips)} - Tempo: {summary[2]}")
else:
    print(log)
for reason in dict.fromkeys(skips):
    import unicodedata
    reason = unicodedata.normalize("NFKD", reason).encode("ascii", "ignore").decode("ascii")
    print(f"  Motivo de teste ignorado: {reason}")
print(f"  Log completo: {sys.argv[1]}")
TESTS
else
    cat "$out/testes.log" >&2
    printf 'Demonstracao interrompida. Log: %s/testes.log\n' "$out" >&2
    exit 1
fi

section 'ETAPA 2 DE 3 - Analisando o PCAP e conferindo o SHA-256'
if ! python3 analyzer.py "$pcap" --output-dir "$out" --expect-sha256 "$expected_sha256" >"$out/analise.log" 2>&1; then
    cat "$out/analise.log" >&2
    printf 'Analise interrompida. Resultados e logs: %s\n' "$out" >&2
    exit 1
fi

python3 - "$out" "$filter_ip" "$filter_port" "$filter_state" <<'RESULTS'
import csv
import json
import os
from collections import Counter
from pathlib import Path
import sys
import unicodedata

out = Path(sys.argv[1])
ip, port, state = sys.argv[2:]
report = json.loads((out / "relatorio.json").read_text(encoding="utf-8"))
capture = report["capture"]
source = report["source"]
attempts = report["attempts"]

def plain(value):
    return unicodedata.normalize("NFKD", str(value)).encode("ascii", "replace").decode("ascii")

def field(label, value):
    print(f"  {label:<24}: {plain(value)}")

def heading(title):
    colored = (os.environ.get("CYBERLAB_COLOR", "1") == "1"
               and sys.stdout.isatty() and "NO_COLOR" not in os.environ
               and os.environ.get("TERM", "dumb") != "dumb")
    start, end = ("\033[1;36m", "\033[0m") if colored else ("", "")
    print("\n" + start + "  " + "-" * 66)
    print("  " + title)
    print("  " + "-" * 66 + end)

heading("DADOS DA CAPTURA")
field("Arquivo", source["name"])
field("Tamanho do arquivo", f"{source['size_bytes']:,} bytes")
field("Formato / enlace", f"{source['format']} / {source['linktype_name']}")
field("Primeiro pacote (UTC)", capture["first_utc"] or "indisponivel")
field("Ultimo pacote (UTC)", capture["last_utc"] or "indisponivel")
duration = capture.get("duration_ns")
field("Intervalo da captura", f"{duration / 1_000_000_000:.6f} s" if duration is not None else "indisponivel")
field("Analise realizada (UTC)", report["analyzed_at_utc"])
field("Pacotes / TCP", f"{capture['packets']} / {capture['tcp_packets']}")
field("Pacotes ignorados", capture["skipped_packets"])
field("Pacotes truncados", capture["snaplen_truncated_packets"])
field("Regressoes de timestamp", capture["timestamp_regressions"])
field("Fluxos direcionais", len(report["tcp_flows"]))
field("Janela de correlacao", f"{report['method']['window_seconds']} s")
field("SHA-256", "CONFERIDO" if source["expected_sha256_matches"] is True else "NAO CONFERIDO")
print("  " + source["sha256"])
print("  Zero ignorados nao comprova ausencia de perdas na rede.")

heading("RESUMO GLOBAL - TODAS AS DIRECOES")
field("Total de tentativas", len(attempts))
for status, count in sorted(report["status_counts"].items()):
    field(status, count)
with (out / "portas.csv").open(encoding="utf-8-sig", newline="") as stream:
    rows = list(csv.DictReader(stream))
field("Pares IP/porta destino", len(rows))
print("\n  DESTINO           TENTATIVAS  ESTADOS DAS TENTATIVAS")
for destination in sorted({a["server_ip"] for a in attempts}):
    counts = Counter(a["status"] for a in attempts if a["server_ip"] == destination)
    states = "; ".join(f"{key}={value}" for key, value in sorted(counts.items()))
    print(f"  {destination:<16} {sum(counts.values()):>10}  {plain(states)}")
print("  Cada tentativa tem um iniciador e um destino.")
print("  Conexoes para o Raspberry tambem entram no resumo global.")

heading("ETAPA 3 DE 3 - CONSULTA DE PORTAS DE DESTINO")
selected = []
for row in rows:
    if ip and ip != "todos" and row["server_ip"] != ip:
        continue
    if port and int(row["server_port"]) != int(port):
        continue
    if state and state != "todos" and row["classification"] != state:
        continue
    selected.append(row)
selected.sort(key=lambda r: (r["server_ip"], int(r["server_port"])))
field("IP de destino", ip or "todos")
field("Porta", port or "todas")
field("Estado da porta", state or "todos")
scoped = [r for r in rows if not ip or ip == "todos" or r["server_ip"] == ip]
field("Portas no destino", len(scoped))
field("Linhas selecionadas", len(selected))
print()
print(f"  {'IP DE DESTINO':<16} {'PORTA':>6}  {'ESTADO':<15} {'TENTATIVAS':>10}")
print("  " + "-" * 61)
colors = (os.environ.get("CYBERLAB_COLOR") == "1" and sys.stdout.isatty()
          and "NO_COLOR" not in os.environ and os.environ.get("TERM", "dumb") != "dumb")
for row in selected:
    label = f"{plain(row['classification']):<15}"
    if colors:
        color = {"aberta": "32", "fechada": "31"}.get(row["classification"], "33")
        label = f"\033[{color}m{label}\033[0m"
    print(f"  {row['server_ip']:<16} {row['server_port']:>6}  {label} {row['attempts']:>10}")
if not selected:
    print("  Nenhuma porta corresponde aos filtros.")

heading("EVIDENCIAS DAS TENTATIVAS SELECIONADAS")
keys = {(r["server_ip"], int(r["server_port"])) for r in selected}
matching = [a for a in attempts if (a["server_ip"], a["server_port"]) in keys]
print("  Referencias numeradas na ordem dos pacotes do PCAP.")
print("  O filtro de estado e da porta; abaixo estao suas tentativas.")
for attempt in matching[:12]:
    print(f"\n  Tentativa {attempt['id']} - {plain(attempt['status'])}")
    print(f"    Origem : {attempt['client_ip']}:{attempt['client_port']}")
    print(f"    Destino: {attempt['server_ip']}:{attempt['server_port']}")
    for key, label in (("syn_packet", "SYN"), ("synack_packet", "SYN/ACK"),
                       ("ack_packet", "ACK"), ("rst_packet", "RST/ACK")):
        packet = attempt.get(key)
        if packet is not None:
            print(f"    {label:<7}: pacote {packet}")
    print(f"    Retransmissoes SYN: {attempt['syn_retransmissions']}")
if not matching:
    print("  Sem tentativas para os filtros escolhidos.")
if len(matching) > 12:
    print(f"\n  Mostradas 12 de {len(matching)} tentativas; demais no JSON/CSV.")
print("\n  Handshake completo nao comprova login, servico ou vulnerabilidade.")

heading("ARQUIVOS GERADOS")
for filename, description in (
    ("relatorio.json", "Metadados, hash e evidencias completas"),
    ("portas.csv", "Resumo por IP e porta de destino"),
    ("tentativas.csv", "Tentativas e referencias dos pacotes"),
    ("fluxos-tcp.csv", "Pacotes, bytes e flags por direcao"),
    ("testes.log", "Testes sobre o PCAP original"),
    ("analise.log", "Saida do analisador sobre o PCAP Wi-Fi"),
):
    path = out / filename
    size = f"{path.stat().st_size:,} bytes" if path.is_file() else "nao encontrado"
    print(f"  {filename:<19} {size:>14}  {description}")
print(f"\n  Pasta: {plain(out)}")
print("  Os relatorios completos nao sao limitados pelos filtros.")
heading("OUTRAS CONSULTAS")
print("  Porta especifica : sh demonstrar.sh --porta 445")
print("  Todas do notebook: sh demonstrar.sh --estado todos")
print("  Todas as abertas : sh demonstrar.sh --ip todos --estado aberta")
print("  Destino Raspberry: sh demonstrar.sh --ip 10.159.233.58 --estado todos")

RESULTS

section 'Concluido. Use --ajuda para consultar os filtros disponiveis.'
