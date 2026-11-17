"""PCAPs sintéticos são fixtures de teste, nunca evidência do experimento."""

import contextlib
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from collections import Counter

from cyberlab.analyzer import AnalysisError, analyze, flags_text, main, write_reports


def tcp(sport=45000, dport=22, seq=100, ack=0, flags=2,
        src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x01", payload=b"", fragment=0):
    # Checksums zero: o analisador não valida checksums (limitação documentada).
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 4096, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, fragment, 64, 6, 0, src, dst)
    return b"\x00" * 12 + b"\x08\x00" + ip + segment


def syn(**kw):
    return tcp(**kw)


def synack(**kw):
    return tcp(sport=22, dport=45000, seq=900, ack=101, flags=18, **kw)


def final_ack(**kw):
    return tcp(seq=101, ack=901, flags=16, **kw)


def pcap(packets, endian="<", ns=False, linktype=1):
    magic = (b"\x4d\x3c\xb2\xa1" if ns else b"\xd4\xc3\xb2\xa1")
    if endian == ">":
        magic = magic[::-1]
    result = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 262144, linktype)
    for i, packet in enumerate(packets):
        if isinstance(packet, tuple):
            second, fraction, packet = packet
        else:
            second, fraction = 1_700_000_000, i * 100
        result += struct.pack(endian + "IIII", second, fraction, len(packet), len(packet)) + packet
    return result


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "fixture.pcap"

    def run_capture(self, packets, **kw):
        self.path.write_bytes(pcap(packets, **kw))
        return analyze(self.path)

    def test_complete_handshake_and_later_client_reset(self):
        report = self.run_capture([syn(), synack(), final_ack(), tcp(seq=101, ack=901, flags=20)])
        attempt = report["attempts"][0]
        self.assertEqual(attempt["status"], "aberta")
        self.assertEqual((attempt["syn_packet"], attempt["synack_packet"], attempt["ack_packet"]), (1, 2, 3))
        self.assertEqual(report["capture"]["tcp_packets"], 4)
        self.assertEqual(report["ports"][0]["classification"], "aberta")
        self.assertEqual(sum(f["packets"] for f in report["tcp_flows"]), 4)

    def test_closed_validates_ack_and_direction(self):
        report = self.run_capture([syn(), tcp(sport=22, dport=45000, seq=0, ack=101, flags=20)])
        self.assertEqual(report["status_counts"], {"fechada": 1})
        self.assertEqual(report["attempts"][0]["rst_packet"], 2)

    def test_no_false_closed_or_open_for_wrong_sequence_tuple_or_direction(self):
        bad_responses = [tcp(sport=22, dport=45000, ack=102, flags=20),
                         tcp(sport=23, dport=45000, ack=101, flags=20),
                         tcp(ack=101, flags=20), tcp(sport=22, dport=45000, flags=4)]
        for response in bad_responses:
            with self.subTest(response=response):
                r = self.run_capture([syn(), response])
                self.assertEqual(r["attempts"][0]["status"], "sem_resposta")
        r = self.run_capture([syn(), synack(), tcp(seq=101, ack=902, flags=16)])
        self.assertEqual(r["attempts"][0]["status"], "synack_sem_ack")

    def test_missing_syn_and_missing_ack_are_inconclusive(self):
        self.assertEqual(self.run_capture([synack(), final_ack()])["attempts"], [])
        r = self.run_capture([syn(), synack()])
        self.assertEqual(r["ports"][0]["classification"], "inconclusiva")
        self.assertEqual(r["status_counts"], {"synack_sem_ack": 1})

    def test_retransmission_and_port_reuse(self):
        r = self.run_capture([syn(), syn(), synack(), synack(), final_ack(),
                              syn(seq=200), tcp(sport=22, dport=45000, ack=201, flags=20)])
        self.assertEqual(r["status_counts"], {"aberta": 1, "fechada": 1})
        self.assertEqual(r["ports"][0]["classification"], "mista")
        self.assertEqual(r["attempts"][0]["syn_retransmissions"], 1)

    def test_changed_server_isn_is_ambiguous(self):
        r = self.run_capture([syn(), synack(), tcp(sport=22, dport=45000, seq=901, ack=101, flags=18), final_ack()])
        self.assertEqual(r["status_counts"], {"resposta_ambigua": 1})

    def test_wraparound_and_ecn_flags(self):
        r = self.run_capture([tcp(seq=0xFFFFFFFF, flags=0xC2),
                              tcp(sport=22, dport=45000, seq=0xFFFFFFFF, ack=0, flags=0x52),
                              tcp(seq=0, ack=0, flags=16)])
        self.assertEqual(r["status_counts"], {"aberta": 1})

    def test_reset_after_synack_does_not_mean_closed(self):
        r = self.run_capture([syn(), synack(), tcp(sport=22, dport=45000, ack=101, flags=20)])
        self.assertEqual(r["status_counts"], {"reset_apos_synack": 1})

    def test_fast_open_and_simultaneous_open_are_not_classified(self):
        r = self.run_capture([syn(payload=b"test"), synack(), final_ack()])
        self.assertEqual(r["status_counts"], {"nao_suportado_syn_com_dados": 1})
        r = self.run_capture([syn(), tcp(sport=22, dport=45000, seq=900)])
        self.assertEqual(r["status_counts"], {"abertura_simultanea": 2})

    def test_timeout_and_timestamp_regression(self):
        r = self.run_capture([(100, 0, syn()), (161, 0, synack()), (99, 0, final_ack())])
        self.assertEqual(r["status_counts"], {"sem_resposta": 1})
        self.assertEqual(r["capture"]["timestamp_regressions"], 1)
        self.assertEqual(r["capture"]["duration_ns"], 62_000_000_000)

    def test_all_classic_magic_variants(self):
        for endian in ("<", ">"):
            for ns in (False, True):
                with self.subTest(endian=endian, ns=ns):
                    r = self.run_capture([syn(), synack(), final_ack()], endian=endian, ns=ns)
                    self.assertEqual(r["status_counts"], {"aberta": 1})
                    self.assertEqual(r["source"]["timestamp_resolution"], "ns" if ns else "us")

    def test_supported_linktypes_and_vlan(self):
        raw = syn()[14:]
        for linktype, frame in [(0, struct.pack("<I", 2) + raw), (108, struct.pack(">I", 2) + raw),
                                (101, raw), (228, raw), (113, b"\0" * 14 + b"\x08\0" + raw),
                                (276, b"\x08\0" + b"\0" * 18 + raw),
                                (1, b"\0" * 12 + b"\x81\0\0\1\x08\0" + raw)]:
            with self.subTest(linktype=linktype):
                r = self.run_capture([frame], linktype=linktype)
                self.assertEqual(r["capture"]["tcp_packets"], 1)

    def test_skips_fragments_non_ip_and_malformed_tcp(self):
        invalid = bytearray(syn())
        invalid[46] = 0xF0  # TCP data offset exceeds IP total length
        r = self.run_capture([syn(fragment=0x2000), b"\0" * 12 + b"\x08\x06" + b"\0" * 28,
                              b"\0", syn()[:-1], bytes(invalid)])
        self.assertEqual(r["capture"]["skipped_packets"], 5)
        self.assertEqual(r["capture"]["tcp_packets"], 0)

    def test_invalid_or_truncated_container_is_fatal(self):
        valid = pcap([syn()])
        for data in (b"", b"\x0a\x0d\x0d\x0a" + b"\0" * 20,
                     valid[:-1], valid + b"\0", pcap([], linktype=999)):
            with self.subTest(data=data[:24]):
                self.path.write_bytes(data)
                with self.assertRaises(AnalysisError):
                    analyze(self.path)

    def test_invalid_lengths_and_timestamp(self):
        data = bytearray(pcap([syn()]))
        for offset, value in ((28, 1_000_000), (32, 262145), (36, 1)):
            broken = bytearray(data)
            struct.pack_into("<I", broken, offset, value)
            self.path.write_bytes(broken)
            with self.assertRaises(AnalysisError):
                analyze(self.path)

    def test_hash_and_empty_capture(self):
        r = self.run_capture([])
        self.assertEqual(r["source"]["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertIsNone(r["capture"]["first_utc"])
        for kw in ({"expected_sha256": "0" * 64}, {"expected_sha256": "wrong"},
                   {"window_seconds": -1}, {"window_seconds": float("nan")}, {"window_seconds": float("inf")}):
            with self.assertRaises(AnalysisError):
                analyze(self.path, **kw)

    def test_reports_roundtrip_refuse_overwrite_and_preserve_source(self):
        r = self.run_capture([syn(), synack(), final_ack()])
        before = self.path.read_bytes()
        out = Path(self.temp.name) / "reports"
        paths = write_reports(r, out, self.path)
        self.assertEqual(json.loads(paths[0].read_text(encoding="utf-8")), r)
        with paths[1].open(encoding="utf-8-sig", newline="") as source:
            self.assertEqual(list(csv.DictReader(source))[0]["classification"], "aberta")
        with self.assertRaises(AnalysisError):
            write_reports(r, out, self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_cli_success_and_bad_hash_no_reports(self):
        self.run_capture([syn()])
        output = Path(self.temp.name) / "cli"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.path), "--output-dir", str(output)]), 0)
        self.assertTrue((output / "relatorio.json").is_file())
        failed = Path(self.temp.name) / "failed"
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.path), "--output-dir", str(failed), "--expect-sha256", "0" * 64]), 1)
        self.assertFalse(failed.exists())


REAL_PCAP = Path(os.environ.get("CYBERLAB_TEST_PCAP", str(Path.home() / "Downloads" / "experimento-nmap.pcap")))
REAL_SHA256 = "ddd44c144ea60620c3fcf4a1e2ef9c7e53ed643b291642f11c896322f6c59a8e"
TSHARK = os.environ.get("CYBERLAB_TSHARK") or shutil.which("tshark")
if not TSHARK:
    candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Wireshark" / "tshark.exe"
    TSHARK = str(candidate) if candidate.is_file() else None


@unittest.skipUnless(REAL_PCAP.is_file(), "PCAP real indisponível; defina CYBERLAB_TEST_PCAP")
class RealCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze(REAL_PCAP, expected_sha256=REAL_SHA256)

    def test_real_capture_totals(self):
        r = self.report
        self.assertEqual(r["source"]["size_bytes"], 160208)
        self.assertEqual(r["capture"]["packets"], 2002)
        self.assertEqual(r["capture"]["tcp_packets"], 2002)
        self.assertEqual(r["capture"]["skipped_packets"], 0)
        self.assertEqual(r["status_counts"], {"fechada": 999, "aberta": 1})
        self.assertEqual(len(r["ports"]), 1000)
        self.assertEqual(len(r["tcp_flows"]), 2000)

    def test_real_ssh_handshake_and_telnet_reset(self):
        a = next(a for a in self.report["attempts"] if a["server_port"] == 22)
        self.assertEqual(a["status"], "aberta")
        self.assertEqual([e["packet"] for e in a["evidence"]], [19, 20, 21])
        self.assertEqual((a["client_ip"], a["server_ip"]), ("127.0.0.1", "127.0.0.1"))
        b = next(a for a in self.report["attempts"] if a["server_port"] == 23)
        self.assertEqual(b["status"], "fechada")
        self.assertEqual([e["packet"] for e in b["evidence"]], [31, 32])

    @unittest.skipUnless(TSHARK, "TShark indisponível para comparação independente")
    def test_real_all_evidence_and_directional_flows_match_tshark(self):
        fields = ["frame.number", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
                  "tcp.flags", "tcp.seq_raw", "tcp.ack_raw"]
        command = [TSHARK, "-n", "-r", str(REAL_PCAP), "-Y", "tcp", "-T", "fields"]
        for field in fields:
            command.extend(["-e", field])
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        rows = {int(row[0]): row for row in csv.reader(result.stdout.splitlines(), delimiter="\t")}
        self.assertEqual(len(rows), self.report["capture"]["tcp_packets"])
        flow_counts = Counter((r[1], int(r[2]), r[3], int(r[4])) for r in rows.values())
        self.assertEqual(flow_counts, Counter({(f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"]):
                                               f["packets"] for f in self.report["tcp_flows"]}))
        for attempt in self.report["attempts"]:
            forward = (attempt["client_ip"], attempt["client_port"], attempt["server_ip"], attempt["server_port"])
            reverse = (forward[2], forward[3], forward[0], forward[1])
            for evidence in attempt["evidence"]:
                row = rows[evidence["packet"]]
                self.assertEqual((int(row[6]), int(row[7])), (evidence["seq"], evidence["ack"]))
                self.assertEqual(flags_text(int(row[5], 16)), evidence["flags"])
                expected = reverse if evidence["packet"] in (attempt["synack_packet"], attempt["rst_packet"]) else forward
                self.assertEqual((row[1], int(row[2]), row[3], int(row[4])), expected)


if __name__ == "__main__":
    unittest.main()
