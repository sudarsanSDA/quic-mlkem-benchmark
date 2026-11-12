#!/usr/bin/env python3
"""Automated QUIC + ML-KEM network-namespace benchmark orchestrator."""

import argparse
import csv
import os
import re
import select
import signal
import subprocess
import sys
import time
from typing import Dict, List

from pcap_utils import analyze_pcap

DEFAULT_CIPHERS = ["X25519", "ML-KEM-512", "ML-KEM-768", "X25519-ML-KEM-768"]
DEFAULT_RTTS = [20, 80, 160]
DEFAULT_LOSSES = [0, 1, 3, 5]
DEFAULT_MTUS = [1500]
DEFAULT_ITERATIONS = 50

PCAP_DIR = "runs/pcap"
RESULTS_FILE = "benchmark_results.csv"

CSV_HEADER = [
    "Run_ID",
    "Cipher",
    "Target_RTT",
    "Target_Loss",
    "MTU",
    "HCT_ms",
    "Total_Bytes_Sent_Client",
    "Total_Bytes_Sent_Server",
    "Packets_Client",
    "Packets_Server",
    "Total_UDP_Bytes_Client",
    "Total_UDP_Bytes_Server",
    "Client_Flight1_UDP_Bytes",
    "Client_PreVal_UDP_Bytes",
    "Server_PreVal_UDP_Bytes",
    "Amp_Limit_3x_UDP_Bytes",
    "Amp_Ratio",
    "Amp_Budget_Util",
    "KEM_KeyGen_ms",
    "KEM_Encaps_ms",
    "KEM_Decaps_ms",
    "Crypto_Total_ms",
    "Negotiated_Group",
    "KEM_Backend",
    "Secret_Match",
    "Asset_Verified",
]


def ensure_cert_exists() -> None:
    os.makedirs("tests", exist_ok=True)
    if not os.path.exists("tests/ssl_cert.pem") or not os.path.exists("tests/ssl_key.pem"):
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                "tests/ssl_key.pem",
                "-out",
                "tests/ssl_cert.pem",
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def run_cmd_ns(ns: str, cmd: List[str], **kwargs) -> subprocess.Popen:
    full_cmd = ["ip", "netns", "exec", ns] + cmd
    return subprocess.Popen(full_cmd, **kwargs)


def parse_kv_lines(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("SERVER_"):
            k, v = line.strip().split("=", 1)
            parsed[k.strip()] = v.strip()
    return parsed


def parse_server_handshake(text: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("SERVER_HANDSHAKE "):
            for m in re.finditer(r"(\w+)=([^\s]+)", line):
                info[m.group(1)] = m.group(2)
            break
    return info


def setup_env(results_file: str, append: bool) -> None:
    ensure_cert_exists()
    os.makedirs(PCAP_DIR, exist_ok=True)
    write_header = (not append) or (not os.path.exists(results_file)) or (os.path.getsize(results_file) == 0)
    if not append and os.path.exists(results_file):
        os.remove(results_file)
    if write_header:
        with open(results_file, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(CSV_HEADER)


def run_verification_suite(py_bin: str, backend: str | None, require_native: bool) -> None:
    cmd = [py_bin, "verify_mlkem_integration.py", "--json-out", "results/crypto_verification.json"]
    if backend:
        cmd.extend(["--backend", backend])
    if require_native:
        cmd.append("--require-native-backend")
    print("Running pre-benchmark ML-KEM cryptographic verification suite...")
    subprocess.run(cmd, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="QUIC ML-KEM Benchmark Orchestrator")
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Run 2 iterations with X25519 and ML-KEM-768 at 20ms RTT / 0% loss",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Run verify_mlkem_integration.py and exit without running full netns matrix",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip pre-benchmark cryptographic verification check",
    )
    parser.add_argument(
        "--backend",
        type=str,
        default=None,
        choices=["liboqs", "cryptography", "kyber_py"],
        help="Force specific FIPS 203 backend (defaults to auto-detect)",
    )
    parser.add_argument(
        "--allow-pure-python",
        action="store_true",
        help="Allow pure-Python kyber_py during verification (disabled by default for timed benchmarks)",
    )
    parser.add_argument("--ciphers", nargs="+", default=None, help="Subset of cipher suites")
    parser.add_argument("--rtts", nargs="+", type=int, default=None, help="Subset of RTTs (ms)")
    parser.add_argument("--losses", nargs="+", type=float, default=None, help="Subset of loss rates (%)")
    parser.add_argument("--iterations", type=int, default=None, help="Iterations per condition")
    parser.add_argument("--results-file", type=str, default=RESULTS_FILE, help="Output CSV path")
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing CSV instead of overwriting",
    )
    args = parser.parse_args()

    py_bin = sys.executable

    if args.verify_only:
        run_verification_suite(py_bin, args.backend, not args.allow_pure_python)
        return

    if not args.skip_verify:
        run_verification_suite(py_bin, args.backend, not args.allow_pure_python)

    ciphers = args.ciphers or list(DEFAULT_CIPHERS)
    rtts = args.rtts or list(DEFAULT_RTTS)
    losses = args.losses or list(DEFAULT_LOSSES)
    mtus = list(DEFAULT_MTUS)
    iterations = args.iterations or DEFAULT_ITERATIONS

    if args.smoke_test:
        ciphers = args.ciphers or ["X25519", "ML-KEM-768"]
        rtts = args.rtts or [20]
        losses = args.losses or [0]
        iterations = args.iterations or 2

    setup_env(args.results_file, append=args.append)

    run_id = 0
    total_runs = len(ciphers) * len(rtts) * len(losses) * len(mtus) * iterations

    with open(args.results_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        for cipher in ciphers:
            for mtu in mtus:
                for rtt in rtts:
                    for loss in losses:
                        loss_str = str(int(loss)) if float(loss).is_integer() else str(loss)
                        subprocess.run(
                            ["./apply_netem.sh", str(rtt), loss_str, str(mtu)],
                            check=True,
                            stdout=subprocess.DEVNULL,
                        )

                        for i in range(iterations):
                            run_id += 1
                            print(
                                f"Run {run_id}/{total_runs} | {cipher} | RTT={rtt}ms Loss={loss_str}% MTU={mtu} | iter={i+1}"
                            )

                            pcap_file = os.path.join(
                                PCAP_DIR, f"{cipher}_{rtt}_{loss_str}_{i}.pcap"
                            )
                            secrets_file = os.path.join(
                                PCAP_DIR, f"{cipher}_{rtt}_{loss_str}_{i}.keys"
                            )
                            if os.path.exists(secrets_file):
                                os.remove(secrets_file)
                            if os.path.exists(pcap_file):
                                os.remove(pcap_file)

                            server_cmd = [
                                py_bin,
                                "quic_engine.py",
                                "server",
                                "--cipher",
                                cipher,
                            ]
                            if args.backend:
                                server_cmd.extend(["--backend", args.backend])

                            server_proc = run_cmd_ns(
                                "server_ns",
                                server_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                            )

                            server_ready = False
                            while True:
                                line = server_proc.stdout.readline()
                                if "SERVER_READY" in line:
                                    server_ready = True
                                    break
                                if server_proc.poll() is not None:
                                    err = server_proc.stderr.read()
                                    print(f"Error: server failed to start:\n{err}", file=sys.stderr)
                                    break

                            if not server_ready:
                                server_proc.kill()
                                server_proc.wait()
                                continue

                            # --immediate-mode bypasses libpcap TPACKET_V3 block buffering so every
                            # handshake packet flushes cleanly before teardown; -Z root retains
                            # capture directory access. Wait on "listening on" before starting client.
                            tcpdump_cmd = [
                                "tcpdump",
                                "--immediate-mode",
                                "-Z",
                                "root",
                                "-U",
                                "-n",
                                "-s",
                                "0",
                                "-i",
                                "veth_server",
                                "-w",
                                pcap_file,
                                "udp",
                                "port",
                                "4433",
                            ]
                            tcpdump_proc = run_cmd_ns(
                                "server_ns",
                                tcpdump_cmd,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE,
                            )

                            td_buf = bytearray()
                            td_fd = tcpdump_proc.stderr.fileno() if tcpdump_proc.stderr else None
                            td_deadline = time.monotonic() + 3.0
                            while td_fd is not None and time.monotonic() < td_deadline:
                                if tcpdump_proc.poll() is not None:
                                    break
                                rlist, _, _ = select.select([td_fd], [], [], 0.05)
                                if rlist:
                                    chunk = os.read(td_fd, 4096)
                                    if not chunk:
                                        break
                                    td_buf.extend(chunk)
                                    if b"listening on" in td_buf:
                                        break
                            time.sleep(0.05)

                            client_cmd = [
                                py_bin,
                                "quic_engine.py",
                                "client",
                                "--cipher",
                                cipher,
                                "--secrets-log",
                                secrets_file,
                            ]
                            if args.backend:
                                client_cmd.extend(["--backend", args.backend])

                            client_proc = run_cmd_ns(
                                "client_ns",
                                client_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                            )

                            try:
                                client_out, client_err = client_proc.communicate(timeout=30)
                            except subprocess.TimeoutExpired:
                                client_proc.kill()
                                client_out, client_err = client_proc.communicate()
                                print(
                                    f"  Handshake timeout ({cipher} RTT={rtt}ms Loss={loss_str}%)",
                                    file=sys.stderr,
                                )

                            # Allow final UDP packets/flush to settle before stopping capture
                            time.sleep(0.10)
                            tcpdump_proc.send_signal(signal.SIGINT)
                            server_proc.send_signal(signal.SIGINT)
                            try:
                                _td_out, td_err_tail = tcpdump_proc.communicate(timeout=5)
                            except subprocess.TimeoutExpired:
                                tcpdump_proc.kill()
                                _td_out, td_err_tail = tcpdump_proc.communicate()

                            try:
                                server_out, server_err = server_proc.communicate(timeout=5)
                            except subprocess.TimeoutExpired:
                                server_proc.kill()
                                server_out, server_err = server_proc.communicate()

                            c_kv = parse_kv_lines(client_out)
                            s_kv = parse_server_handshake(server_out)

                            hct_ms = float(c_kv["HCT_MS"]) if "HCT_MS" in c_kv else None
                            asset_ok = int(c_kv.get("ASSET_VERIFIED", "0")) == 1
                            if hct_ms is None or client_proc.returncode != 0 or not asset_ok:
                                print(
                                    f"  Handshake failed ({cipher} rc={client_proc.returncode}): {client_err.strip()}",
                                    file=sys.stderr,
                                )
                                continue

                            pcap_stats = analyze_pcap(
                                pcap_file,
                                client_ip="10.0.0.1",
                                server_ip="10.0.0.2",
                                server_port=4433,
                            )
                            if pcap_stats["total_udp_bytes_client"] == 0:
                                td_msg = (bytes(td_buf) + (td_err_tail or b"")).decode(
                                    "utf-8", errors="replace"
                                )
                                print(
                                    f"  Warning: empty PCAP ({pcap_file}); tcpdump: {td_msg.strip()}",
                                    file=sys.stderr,
                                )

                            kg_ms = float(c_kv.get("KEM_KEYGEN_MS", "0.0"))
                            enc_ms = float(s_kv.get("encaps_ms", "0.0"))
                            dec_ms = float(c_kv.get("KEM_DECAPS_MS", "0.0"))
                            crypto_total_ms = round(kg_ms + enc_ms + dec_ms, 4)

                            c_ss = c_kv.get("KEM_SS_HASH", "")
                            s_ss = s_kv.get("ss_hash", "")
                            secret_match = int(bool(c_ss and s_ss and c_ss == s_ss))
                            neg_group = c_kv.get("NEGOTIATED_GROUP", "")
                            backend_used = c_kv.get("KEM_BACKEND", s_kv.get("backend", ""))

                            print(
                                f"  HCT={hct_ms:.2f}ms | Crypto={crypto_total_ms:.3f}ms | "
                                f"PreVal(C={pcap_stats['client_preval_udp_bytes']}B, "
                                f"S={pcap_stats['server_preval_udp_bytes']}B) | Match={secret_match}"
                            )

                            writer.writerow(
                                [
                                    run_id,
                                    cipher,
                                    rtt,
                                    loss_str,
                                    mtu,
                                    round(hct_ms, 3),
                                    pcap_stats["total_ip_bytes_client"],
                                    pcap_stats["total_ip_bytes_server"],
                                    pcap_stats["packets_client"],
                                    pcap_stats["packets_server"],
                                    pcap_stats["total_udp_bytes_client"],
                                    pcap_stats["total_udp_bytes_server"],
                                    pcap_stats["client_flight1_udp_bytes"],
                                    pcap_stats["client_preval_udp_bytes"],
                                    pcap_stats["server_preval_udp_bytes"],
                                    pcap_stats["amp_limit_3x_udp_bytes"],
                                    pcap_stats["amp_ratio"],
                                    pcap_stats["amp_budget_utilization"],
                                    round(kg_ms, 4),
                                    round(enc_ms, 4),
                                    round(dec_ms, 4),
                                    crypto_total_ms,
                                    neg_group,
                                    backend_used,
                                    secret_match,
                                    int(asset_ok),
                                ]
                            )
                            f.flush()


if __name__ == "__main__":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("Error: root privileges required to manage netns and tcpdump")
    main()
