"""Leitor PCAP clássico e correlação conservadora de handshakes TCP/IPv4.

Somente biblioteca padrão. Não captura tráfego nem envia pacotes.
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import struct
import sys

__version__ = "0.1.0"

SYN, ACK, RST, FIN = 2, 16, 4, 1
MASK32 = 0xFFFFFFFF
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}
LINKTYPES = {0: "NULL", 1: "Ethernet", 101: "RAW", 108: "LOOP",
             113: "Linux SLL", 228: "IPv4", 276: "Linux SLL2"}
LIMITATIONS = [
    "Somente PCAP clássico e TCP/IPv4; PCAPNG deve ser convertido antes.",
    "Sem remontagem de fragmentos IP, validação de checksums ou análise de aplicação.",
    "Ordem do arquivo e janela temporal limitam a correlação; pacotes ausentes não são inferidos.",
    "SYN com dados (TCP Fast Open), abertura simultânea e respostas ambíguas não são classificados.",
    "Aberta/fechada descrevem o padrão observado, não autenticam o emissor nem o serviço.",
    "SHA-256 identifica os bytes analisados; não comprova sozinho origem ou cadeia de custódia.",
]


class AnalysisError(ValueError):
    """Entrada inválida ou formato não suportado."""


class SkipPacket(Exception):
    """Pacote não analisável; a razão é contabilizada no relatório."""


@dataclass(frozen=True)
class TCPPacket:
    number: int
    timestamp_ns: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload_bytes: int
    captured_bytes: int

    @property
    def flow(self):
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    @property
    def reverse(self):
        return (self.dst_ip, self.dst_port, self.src_ip, self.src_port)


def utc_ns(value):
    if value is None:
        return None
    seconds, ns = divmod(value, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S") + f".{ns:09d}Z"


def flags_text(flags):
    return "|".join(name for bit, name in (
        (FIN, "FIN"), (SYN, "SYN"), (RST, "RST"), (8, "PSH"),
        (ACK, "ACK"), (32, "URG"), (64, "ECE"), (128, "CWR"),
        (256, "NS")) if flags & bit) or "NONE"


def decode_tcp(data, linktype, number, timestamp_ns):
    """Remove enlace e valida comprimentos antes de ler cada cabeçalho."""
    captured_bytes = len(data)

    def require(length):
        if len(data) < length:
            raise SkipPacket("cabecalho_incompleto")

    if linktype == 1:
        require(14)
        protocol = struct.unpack_from("!H", data, 12)[0]
        offset = 14
        while protocol in (0x8100, 0x88A8, 0x9100):
            require(offset + 4)
            protocol = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
        data = data[offset:]
    elif linktype in (113, 276):
        require(16 if linktype == 113 else 20)
        protocol = struct.unpack_from("!H", data, 14 if linktype == 113 else 0)[0]
        data = data[16 if linktype == 113 else 20:]
    elif linktype in (0, 108):
        require(4)
        family = data[:4]
        protocol = 0x0800 if family in (b"\x02\x00\x00\x00", b"\x00\x00\x00\x02") else 0
        data = data[4:]
    else:  # RAW ou IPv4
        protocol = 0x0800
    if protocol != 0x0800:
        raise SkipPacket("nao_ipv4")
    require(20)
    if data[0] >> 4 != 4:
        raise SkipPacket("nao_ipv4")
    ihl = (data[0] & 15) * 4
    total = struct.unpack_from("!H", data, 2)[0]
    if ihl < 20 or total < ihl:
        raise SkipPacket("ipv4_invalido")
    require(ihl)
    if struct.unpack_from("!H", data, 6)[0] & 0x3FFF:
        raise SkipPacket("ipv4_fragmentado")
    if data[9] != 6:
        raise SkipPacket("nao_tcp")
    if len(data) < total:
        raise SkipPacket("ipv4_truncado")
    if total < ihl + 20:
        raise SkipPacket("tcp_invalido")
    src, dst = str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20]))
    tcp = data[ihl:total]
    sport, dport, seq, ack = struct.unpack_from("!HHII", tcp)
    offset = (tcp[12] >> 4) * 4
    if offset < 20 or offset > len(tcp):
        raise SkipPacket("tcp_invalido")
    flags = ((tcp[12] & 1) << 8) | tcp[13]
    return TCPPacket(number, timestamp_ns, src, sport, dst, dport, seq, ack,
                     flags, len(tcp) - offset, captured_bytes)


class Correlator:
    def __init__(self, window_ns):
        self.window_ns = window_ns
        self.attempts = []
        self.active = {}
        self.flows = {}
        self.unmatched_control_packets = 0

    @staticmethod
    def evidence(packet):
        return {"packet": packet.number, "timestamp_ns": packet.timestamp_ns,
                "flags": flags_text(packet.flags), "seq": packet.seq, "ack": packet.ack}

    def feed(self, packet):
        p = packet
        flow = self.flows.setdefault(p.flow, {
            "src_ip": p.src_ip, "src_port": p.src_port,
            "dst_ip": p.dst_ip, "dst_port": p.dst_port,
            "packets": 0, "captured_bytes": 0, "tcp_payload_bytes": 0,
            "first_timestamp_ns": p.timestamp_ns, "last_timestamp_ns": p.timestamp_ns,
            "flags": Counter(),
        })
        flow["packets"] += 1
        flow["captured_bytes"] += p.captured_bytes
        flow["tcp_payload_bytes"] += p.payload_bytes
        flow["first_timestamp_ns"] = min(flow["first_timestamp_ns"], p.timestamp_ns)
        flow["last_timestamp_ns"] = max(flow["last_timestamp_ns"], p.timestamp_ns)
        flow["flags"][flags_text(p.flags)] += 1

        if p.flags & SYN and not p.flags & (ACK | RST | FIN):
            old = self.active.get(p.flow)
            if (old and old["client_isn"] == p.seq and
                    old["status"] in ("sem_resposta", "synack_sem_ack") and
                    0 <= p.timestamp_ns - old["started_ns"] <= self.window_ns):
                old["syn_retransmissions"] += 1
                old["evidence"].append(self.evidence(p))
                return
            attempt = {
                "id": len(self.attempts) + 1, "client_ip": p.src_ip,
                "client_port": p.src_port, "server_ip": p.dst_ip, "server_port": p.dst_port,
                "client_isn": p.seq, "server_isn": None, "started_ns": p.timestamp_ns,
                "status": "nao_suportado_syn_com_dados" if p.payload_bytes else "sem_resposta",
                "syn_packet": p.number, "synack_packet": None, "ack_packet": None,
                "rst_packet": None, "syn_retransmissions": 0,
                "evidence": [self.evidence(p)],
            }
            self.attempts.append(attempt)
            self.active[p.flow] = attempt
            reverse = self.active.get(p.reverse)
            if p.flow == p.reverse:
                attempt["status"] = "resposta_ambigua"
            elif reverse and reverse["status"] in ("sem_resposta", "synack_sem_ack"):
                if 0 <= p.timestamp_ns - reverse["started_ns"] <= self.window_ns:
                    attempt["status"] = reverse["status"] = "abertura_simultanea"
            return

        # Resposta deve inverter IPs E portas e reconhecer o ISN do SYN.
        a = self.active.get(p.reverse)
        if a and 0 <= p.timestamp_ns - a["started_ns"] <= self.window_ns:
            expected_ack = (a["client_isn"] + 1) & MASK32
            if a["status"] in ("sem_resposta", "synack_sem_ack") and p.ack == expected_ack:
                if p.flags & (SYN | ACK) == SYN | ACK and not p.flags & (RST | FIN):
                    if p.payload_bytes:
                        a["status"] = "nao_suportado_syn_com_dados"
                    elif a["server_isn"] is None or a["server_isn"] == p.seq:
                        a["server_isn"] = p.seq
                        a["synack_packet"] = a["synack_packet"] or p.number
                        a["status"] = "synack_sem_ack"
                    else:
                        a["status"] = "resposta_ambigua"
                    a["evidence"].append(self.evidence(p))
                    return
                if p.flags & (RST | ACK) == RST | ACK and not p.flags & (SYN | FIN):
                    a["rst_packet"] = p.number
                    a["status"] = "fechada" if a["status"] == "sem_resposta" else "reset_apos_synack"
                    a["evidence"].append(self.evidence(p))
                    return

        # ACK final deve reconhecer o ISN do servidor e avançar o ISN do cliente.
        a = self.active.get(p.flow)
        if (a and a["status"] == "synack_sem_ack" and
                a["evidence"][-1]["timestamp_ns"] <= p.timestamp_ns and
                0 <= p.timestamp_ns - a["started_ns"] <= self.window_ns and
                p.flags & ACK and not p.flags & (SYN | RST | FIN) and
                p.seq == (a["client_isn"] + 1) & MASK32 and
                p.ack == (a["server_isn"] + 1) & MASK32):
            a["status"] = "aberta"
            a["ack_packet"] = p.number
            a["evidence"].append(self.evidence(p))
            return
        if p.flags & (SYN | RST):
            self.unmatched_control_packets += 1

    def ports(self):
        ports = {}
        for a in self.attempts:
            key = (a["server_ip"], a["server_port"])
            row = ports.setdefault(key, {"server_ip": key[0], "server_port": key[1],
                                         "attempts": 0, "statuses": Counter(), "attempt_ids": []})
            row["attempts"] += 1
            row["statuses"][a["status"]] += 1
            row["attempt_ids"].append(a["id"])
        for row in ports.values():
            states = row["statuses"]
            row["classification"] = (
                "mista" if "aberta" in states and "fechada" in states else
                "aberta" if "aberta" in states else "fechada" if "fechada" in states else "inconclusiva")
        return sorted(ports.values(), key=lambda r: (r["server_ip"], r["server_port"]))


def analyze(path, *, window_seconds=60.0, expected_sha256=None):
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise AnalysisError("A janela temporal deve ser positiva e finita.")
    if expected_sha256 is not None:
        expected_sha256 = expected_sha256.lower()
        if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
            raise AnalysisError("SHA-256 esperado deve conter 64 dígitos hexadecimais.")
    path = Path(path)
    digest = hashlib.sha256()
    correlator = Correlator(int(window_seconds * 1_000_000_000))
    counts = Counter()
    skipped = Counter()
    first = last = previous = None
    with path.open("rb") as source:
        before = os.fstat(source.fileno())

        def read(size):
            data = source.read(size)
            digest.update(data)
            return data

        header = read(24)
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            raise AnalysisError("PCAPNG não suportado. Converta com editcap -F pcap entrada.pcapng saida.pcap.")
        if len(header) != 24 or header[:4] not in MAGICS:
            raise AnalysisError("Cabeçalho PCAP clássico inválido ou incompleto.")
        endian, ns_factor = MAGICS[header[:4]]
        major, minor, _, _, snaplen, network = struct.unpack(endian + "HHIIII", header[4:])
        linktype = network & 0xFFFF
        if (major, minor) != (2, 4) or not snaplen:
            raise AnalysisError("Versão PCAP não suportada ou snaplen inválido.")
        if linktype not in LINKTYPES:
            raise AnalysisError(f"Tipo de enlace não suportado: {linktype}.")
        # Não interpreta os bits adicionais de FCS/reservados nesta versão.
        if network != linktype:
            raise AnalysisError("Metadados adicionais de enlace/FCS não suportados.")
        while True:
            record = read(16)
            if not record:
                break
            if len(record) != 16:
                raise AnalysisError(f"Cabeçalho de registro truncado após pacote {counts['packets']}.")
            sec, frac, included, original = struct.unpack(endian + "IIII", record)
            if frac >= 1_000_000_000 // ns_factor:
                raise AnalysisError("Fração de timestamp inválida.")
            if included > snaplen or included > original or included > 16 * 1024 * 1024:
                raise AnalysisError("Comprimento de registro inválido ou acima do limite de 16 MiB.")
            data = read(included)
            if len(data) != included:
                raise AnalysisError(f"Dados truncados no pacote {counts['packets'] + 1}.")
            counts["packets"] += 1
            counts["captured_bytes"] += included
            counts["original_bytes"] += original
            counts["snaplen_truncated_packets"] += included < original
            timestamp = sec * 1_000_000_000 + frac * ns_factor
            if previous is not None and timestamp < previous:
                counts["timestamp_regressions"] += 1
            previous = timestamp
            first = timestamp if first is None else min(first, timestamp)
            last = timestamp if last is None else max(last, timestamp)
            try:
                packet = decode_tcp(data, linktype, counts["packets"], timestamp)
            except SkipPacket as exc:
                skipped[str(exc)] += 1
                continue
            counts["tcp_packets"] += 1
            correlator.feed(packet)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise AnalysisError("Arquivo mudou durante a leitura; repita sobre uma cópia estável.")
    sha256 = digest.hexdigest()
    if expected_sha256 and sha256 != expected_sha256:
        raise AnalysisError(f"SHA-256 divergente: calculado {sha256}; nenhum relatório gerado.")
    counts["skipped_packets"] = sum(skipped.values())
    # Mantém chaves presentes também em captura vazia.
    for key in ("packets", "tcp_packets", "captured_bytes", "original_bytes",
                "snaplen_truncated_packets", "timestamp_regressions"):
        counts.setdefault(key, 0)
    return {
        "schema_version": "1.0", "analyzer_version": __version__,
        "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": {"name": path.name, "size_bytes": before.st_size, "sha256": sha256,
                   "expected_sha256_matches": True if expected_sha256 else None,
                   "format": "pcap", "linktype": linktype, "linktype_name": LINKTYPES[linktype],
                   "snaplen": snaplen, "timestamp_resolution": "us" if ns_factor == 1000 else "ns"},
        "capture": {**counts, "skipped_reasons": dict(skipped),
                    "first_timestamp_ns": first, "last_timestamp_ns": last,
                    "first_utc": utc_ns(first), "last_utc": utc_ns(last),
                    "duration_ns": last - first if first is not None else 0},
        "method": {"window_seconds": window_seconds, "sequence_ack_validation": True,
                   "packet_numbering": "1-based; ordem dos registros do arquivo"},
        "status_counts": dict(Counter(a["status"] for a in correlator.attempts)),
        "unmatched_syn_rst_packets": correlator.unmatched_control_packets,
        "ports": correlator.ports(), "attempts": correlator.attempts,
        "tcp_flows": sorted(correlator.flows.values(), key=lambda r: (
            r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"])),
        "limitations": LIMITATIONS,
    }


def write_reports(report, output_dir, source_path):
    output_dir = Path(output_dir)
    names = ("relatorio.json", "portas.csv", "tentativas.csv", "fluxos-tcp.csv")
    paths = [output_dir / name for name in names]
    if any(p.resolve() == Path(source_path).resolve() for p in paths):
        raise AnalysisError("A saída não pode substituir a evidência de entrada.")
    if any(p.exists() for p in paths):
        raise AnalysisError("Já existem relatórios nesta pasta. Escolha outra pasta de saída.")
    output_dir.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        with paths[0].open("x", encoding="utf-8", newline="\n") as target:
            created.append(paths[0])
            json.dump(report, target, ensure_ascii=False, indent=2)
            target.write("\n")
        tables = (
            (report["ports"], ["server_ip", "server_port", "classification", "attempts", "statuses", "attempt_ids"]),
            (report["attempts"], ["id", "client_ip", "client_port", "server_ip", "server_port", "status",
                                  "syn_packet", "synack_packet", "ack_packet", "rst_packet",
                                  "syn_retransmissions", "started_ns", "client_isn", "server_isn"]),
            (report["tcp_flows"], ["src_ip", "src_port", "dst_ip", "dst_port", "packets", "captured_bytes",
                                   "tcp_payload_bytes", "first_timestamp_ns", "last_timestamp_ns", "flags"]),
        )
        for path, (rows, fields) in zip(paths[1:], tables):
            with path.open("x", encoding="utf-8-sig", newline="") as target:
                created.append(path)
                writer = csv.DictWriter(target, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: json.dumps(row[key], ensure_ascii=False) if
                                     isinstance(row.get(key), (dict, list)) else row.get(key)
                                     for key in fields})
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return paths


def main(argv=None):
    parser = argparse.ArgumentParser(description="CyberLab Forensic Analyzer — PCAP local TCP/IPv4")
    parser.add_argument("pcap", type=Path, help="arquivo PCAP clássico")
    parser.add_argument("--output-dir", type=Path, default=Path("relatorios"), help="pasta de saída (padrão: relatorios)")
    parser.add_argument("--window-seconds", type=float, default=60.0, help="janela máxima desde o SYN (padrão: 60)")
    parser.add_argument("--expect-sha256", help="interrompe se o hash for diferente do esperado")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        report = analyze(args.pcap, window_seconds=args.window_seconds, expected_sha256=args.expect_sha256)
        paths = write_reports(report, args.output_dir, args.pcap)
    except (OSError, AnalysisError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1
    print(f"CyberLab {__version__} | {report['capture']['packets']} pacotes | {report['capture']['tcp_packets']} TCP")
    print(f"SHA-256: {report['source']['sha256']}")
    print("Tentativas: " + json.dumps(report["status_counts"], ensure_ascii=False, sort_keys=True))
    print(f"Pacotes ignorados: {report['capture']['skipped_packets']}")
    for path in paths:
        print(f"Relatório: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
