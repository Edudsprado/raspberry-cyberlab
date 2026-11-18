#!/bin/sh
# Execute com: sh testar.sh [caminho-do-PCAP-do-experimento-01]
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 1
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
    exec python3 "$script_dir/scripts/run_tests.py" "$@"
elif command -v python >/dev/null 2>&1 && python -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
    exec python "$script_dir/scripts/run_tests.py" "$@"
else
    echo "Python 3.10 ou superior nao encontrado." >&2
    exit 1
fi
