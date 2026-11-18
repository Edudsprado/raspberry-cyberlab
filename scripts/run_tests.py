"""Executa a suite existente e salva resultados locais, sem dependencias extras."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, text):
        for stream in self.streams:
            stream.write(text)
        return len(text)

    def flush(self):
        for stream in self.streams:
            stream.flush()


class TestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = 0

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed += 1


def main():
    parser = argparse.ArgumentParser(
        description="Executa todos os testes do CyberLab e salva log/JSON.")
    parser.add_argument("pcap", nargs="?", type=Path,
                        help="PCAP do experimento 01 (hash conhecido), opcional")
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error("Use Python 3.10 ou superior.")

    root = Path(__file__).resolve().parent.parent
    supplied = args.pcap
    if supplied is None and "CYBERLAB_TEST_PCAP" in os.environ:
        supplied = Path(os.environ["CYBERLAB_TEST_PCAP"])
    if supplied is not None:
        pcap = supplied.expanduser().resolve()
        if not pcap.is_file():
            parser.error(f"PCAP informado nao encontrado: {pcap}")
    else:
        candidates = [Path.home() / "Downloads/experimento-nmap.pcap",
                      Path.home() / "Cyberlab/capturas/expermiremnto-nmap.pcap",
                      Path.home() / "Cyberlab/capturas/experimento-nmap.pcap"]
        pcap = next((path for path in candidates if path.is_file()), None)
    if pcap is not None:
        os.environ["CYBERLAB_TEST_PCAP"] = str(pcap)

    # A suite usa imports de cyberlab; funciona mesmo fora da pasta do projeto.
    sys.path.insert(0, str(root))
    os.chdir(root)
    output_root = root / "relatorios-testes"
    output_root.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
    output = Path(tempfile.mkdtemp(prefix=stamp, dir=output_root))
    with (output / "testes.log").open("w", encoding="utf-8") as log:
        stream = Tee(sys.stdout, log)
        print("CyberLab - testes automatizados", file=stream)
        print(f"Python: {sys.version.split()[0]}", file=stream)
        print(f"PCAP do experimento: {pcap or 'ausente; testes reais serao ignorados'}",
              file=stream)
        suite = unittest.defaultTestLoader.discover(
            start_dir=str(root / "tests"), top_level_dir=str(root))
        result = unittest.TextTestRunner(
            stream=stream, verbosity=2, resultclass=TestResult).run(suite)
        success = result.wasSuccessful() and result.testsRun > 0
        passed = result.passed
        summary = {
            "executed_at_utc": datetime.now(timezone.utc).isoformat(),
            "python": sys.version.split()[0], "platform": sys.platform,
            "pcap_available": pcap is not None, "tests_run": result.testsRun,
            "passed": passed, "skipped": len(result.skipped),
            "failures": len(result.failures), "errors": len(result.errors),
            "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses),
            "success": success, "complete": success and not result.skipped,
            "skipped_tests": [{"test": test.id(), "reason": reason}
                              for test, reason in result.skipped],
        }
        with (output / "resultado.json").open("w", encoding="utf-8") as target:
            json.dump(summary, target, ensure_ascii=False, indent=2)
            target.write("\n")
        status = ("FALHOU" if not success else
                  "OK COM TESTES IGNORADOS" if result.skipped else "OK")
        print(f"\nResultado: {status}", file=stream)
        print(f"Aprovados: {passed}; ignorados: {len(result.skipped)}; "
              f"falhas: {len(result.failures)}; erros: {len(result.errors)}", file=stream)
        print(f"Resultados salvos em: {output}", file=stream)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
