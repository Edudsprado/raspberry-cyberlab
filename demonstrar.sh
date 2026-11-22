#!/bin/sh
# Executa a demonstração do experimento 01 sobre o PCAP já coletado.
set -eu

usage() {
    cat <<'HELP'
Uso: sh demonstrar.sh [PCAP-do-experimento-01] [opções]

  --ip IP          Mostrar somente esse IP de destino
  --porta PORTA    Mostrar somente essa porta de destino
  --estado ESTADO  aberta, fechada, inconclusiva, mista ou todos
  --ajuda          Mostrar esta ajuda

Sem filtros: mostra as portas abertas, mistas e inconclusivas.
Os filtros afetam somente a tabela; os relatórios permanecem completos.
Este script analisa o experimento 01, com hash fixo. Não faz varredura.
HELP
}

pcap="$HOME/Cyberlab/capturas/expermiremnto-nmap.pcap"
custom_pcap=0
filter_ip=''
filter_port=''
filter_state=''
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
        -*) printf 'Opção desconhecida: %s\n' "$1" >&2; exit 2 ;;
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
    if ip:
        ipaddress.IPv4Address(ip)
    if port and (not port.isascii() or not port.isdecimal() or not 0 <= int(port) <= 65535):
        raise ValueError("porta deve ser um número entre 0 e 65535")
    if state not in ("", "aberta", "fechada", "inconclusiva", "mista", "todos"):
        raise ValueError("estado deve ser aberta, fechada, inconclusiva, mista ou todos")
except ValueError as error:
    sys.exit(f"Filtro inválido: {error}")
VALIDATE

color=''
reset=''
if [ -t 1 ] && [ -z "${NO_COLOR+x}" ] && [ "${TERM:-dumb}" != dumb ]; then
    color=$(printf '\033[1;36m')
    reset=$(printf '\033[0m')
fi
section() { printf '\n%s%s%s\n' "$color" "$1" "$reset"; }
case "$pcap" in
    /*) ;;
    *) pcap="$PWD/$pcap" ;;
esac

if [ ! -f "$pcap" ]; then
    printf 'PCAP não encontrado: %s\n' "$pcap" >&2
    exit 2
fi

project_dir=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
cd "$project_dir"
out=$(mktemp -d "$project_dir/relatorios-demonstracao.XXXXXX")
expected_sha256=ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e

section '============================================================'
printf '%s\n' '  RASPBERRY CYBERLAB | Forensic Analyzer 0.1.0' '  Experimento 01 - análise de captura existente'
printf '  PCAP: %s\n' "$pcap"
section '============================================================'
section '[1/3] Verificando o analisador com os testes automatizados'
if CYBERLAB_TEST_PCAP="$pcap" python3 -m unittest discover -v >"$out/testes.log" 2>&1; then
    python3 - "$out/testes.log" <<'TESTS'
import pathlib
import re
import sys
log = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
summary = re.search(r"^Ran (\d+) tests? in (.+)$", log, re.MULTILINE)
skips = re.findall(r"^.*? \.\.\. skipped (.+)$", log, re.MULTILINE)
if summary:
    total = int(summary[1])
    print(f"  Aprovados: {total - len(skips)} | Ignorados: {len(skips)} | Tempo: {summary[2]}")
else:
    print(log)
for reason in dict.fromkeys(skips):
    print(f"  Motivo de teste ignorado: {reason}")
print(f"  Log completo: {sys.argv[1]}")
TESTS
else
    cat "$out/testes.log" >&2
    printf 'Demonstração interrompida. Log: %s/testes.log\n' "$out" >&2
    exit 1
fi

section '[2/3] Analisando o PCAP e conferindo o SHA-256'
if ! python3 analyzer.py "$pcap" --output-dir "$out" --expect-sha256 "$expected_sha256" >"$out/analise.log" 2>&1; then
    cat "$out/analise.log" >&2
    printf 'Análise interrompida. Resultados e logs: %s\n' "$out" >&2
    exit 1
fi

python3 - "$out" "$filter_ip" "$filter_port" "$filter_state" <<'RESULTS'
import csv
import json
import os
from pathlib import Path
import sys

out = Path(sys.argv[1])
ip, port, state = sys.argv[2:]
report = json.loads((out / "relatorio.json").read_text(encoding="utf-8"))
capture = report["capture"]
print(f"  Pacotes: {capture['packets']} | TCP: {capture['tcp_packets']} | Ignorados: {capture['skipped_packets']}")
print("  Tentativas: " + " | ".join(f"{k}: {v}" for k, v in sorted(report["status_counts"].items())))
print("  SHA-256 conferido:")
print(f"  {report['source']['sha256']}")
print("\n[3/3] Consulta de portas de destino")
with (out / "portas.csv").open(encoding="utf-8-sig", newline="") as source:
    rows = list(csv.DictReader(source))
selected = []
for row in rows:
    if ip and row["server_ip"] != ip:
        continue
    if port and int(row["server_port"]) != int(port):
        continue
    if state and state != "todos" and row["classification"] != state:
        continue
    if not (ip or port or state) and row["classification"] == "fechada":
        continue
    selected.append(row)
selected.sort(key=lambda r: (r["server_ip"], int(r["server_port"])))
print(f"  Filtros: IP={ip or 'todos'} | porta={port or 'todas'} | estado={state or ('todos' if ip or port else 'aberta/mista/inconclusiva')}")
print("  " + "-" * 61)
print(f"  {'IP DE DESTINO':<16} {'PORTA':>6}  {'ESTADO':<15} {'TENTATIVAS':>10}")
print("  " + "-" * 61)
colors = sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM", "dumb") != "dumb"
for row in selected:
    label = f"{row['classification']:<15}"
    if colors:
        code = {"aberta": "32", "fechada": "31"}.get(row["classification"], "33")
        label = f"\033[{code}m{label}\033[0m"
    print(f"  {row['server_ip']:<16} {row['server_port']:>6}  {label} {row['attempts']:>10}")
if not selected:
    print("  Nenhuma porta corresponde aos filtros.")
print(f"\n  Exibidas: {len(selected)} de {len(rows)} portas de destino.")
print("  Os relatórios contêm os resultados completos, sem filtros.")
print(f"\n  Resultados e logs: {out}")
print("  relatorio.json | portas.csv | tentativas.csv | fluxos-tcp.csv")
print("  testes.log | analise.log")
RESULTS

section 'Concluído. Use --ajuda para consultar os filtros disponíveis.'
