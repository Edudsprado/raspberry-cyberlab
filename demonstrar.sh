#!/bin/sh
# Executa a demonstração do experimento 01 sobre o PCAP já coletado.
set -eu

if [ "$#" -gt 1 ]; then
    printf 'Uso: sh demonstrar.sh [caminho-do-PCAP-do-experimento-01]\n' >&2
    exit 2
fi

pcap=${1:-"$HOME/Cyberlab/capturas/expermiremnto-nmap.pcap"}
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

printf 'Executando os testes do CyberLab…\n'
if CYBERLAB_TEST_PCAP="$pcap" python3 -m unittest discover -v >"$out/testes.log" 2>&1; then
    cat "$out/testes.log"
else
    cat "$out/testes.log" >&2
    printf 'Demonstração interrompida. Log: %s/testes.log\n' "$out" >&2
    exit 1
fi

printf '\nAnalisando o PCAP do experimento 01…\n'
python3 analyzer.py "$pcap" --output-dir "$out" --expect-sha256 "$expected_sha256"

printf '\nPortas do experimento\n'
awk -F, 'BEGIN { printf "%-16s %-8s %s\n", "IP", "PORTA", "ESTADO" }
    $1 == "127.0.0.1" && ($2 == "22" || $2 == "23") {
        printf "%-16s %-8s %s\n", $1, $2, $3
    }' "$out/portas.csv"
printf '\nLog e relatórios salvos em %s\n' "$out"
