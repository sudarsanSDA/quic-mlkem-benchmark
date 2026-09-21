#!/usr/bin/env python3
import argparse
import csv
import os
import signal
import subprocess
import sys
import time

CIPHERS = ["X25519", "ML-KEM-512", "ML-KEM-768", "X25519-ML-KEM-768"]
RTTS = [20, 80, 160]
LOSSES = [0, 1, 3, 5]
MTUS = [1500]
ITERATIONS = 50

PCAP_DIR = "runs/pcap"
RESULTS_FILE = "benchmark_results.csv"


def ensure_cert_exists():
    os.makedirs("tests", exist_ok=True)
    if not os.path.exists("tests/ssl_cert.pem"):
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


def run_cmd_ns(ns, cmd, **kwargs):
    full_cmd = ["ip", "netns", "exec", ns] + cmd
    return subprocess.Popen(full_cmd, **kwargs)


def setup_env():
    ensure_cert_exists()
    os.makedirs(PCAP_DIR, exist_ok=True)
    if not os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
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
                ]
            )


def main():
    parser = argparse.ArgumentParser(description="QUIC ML-KEM Benchmark Orchestrator")
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Run 1 iteration with X25519 and ML-KEM-768 at 20ms RTT / 0% loss",
    )
    args = parser.parse_args()

    global CIPHERS, RTTS, LOSSES, ITERATIONS
    if args.smoke_test:
        CIPHERS = ["X25519", "ML-KEM-768"]
        RTTS = [20]
        LOSSES = [0]
        ITERATIONS = 1

    setup_env()

    py_bin = sys.executable
    run_id = 0
    total_runs = len(CIPHERS) * len(RTTS) * len(LOSSES) * len(MTUS) * ITERATIONS

    with open(RESULTS_FILE, "a", newline="") as f:
        writer = csv.writer(f)

        for cipher in CIPHERS:
            for mtu in MTUS:
                for rtt in RTTS:
                    for loss in LOSSES:
                        subprocess.run(
                            ["./apply_netem.sh", str(rtt), str(loss), str(mtu)],
                            check=True,
                            stdout=subprocess.DEVNULL,
                        )

                        for i in range(ITERATIONS):
                            run_id += 1
                            print(
                                f"Run {run_id}/{total_runs} | {cipher} | RTT={rtt}ms Loss={loss}% MTU={mtu} | iter={i+1}"
                            )

                            pcap_file = os.path.join(
                                PCAP_DIR, f"{cipher}_{rtt}_{loss}_{i}.pcap"
                            )
                            secrets_file = os.path.join(
                                PCAP_DIR, f"{cipher}_{rtt}_{loss}_{i}.keys"
                            )

                            server_cmd = [
                                py_bin,
                                "quic_engine.py",
                                "server",
                                "--cipher",
                                cipher,
                            ]
                            server_proc = run_cmd_ns(
                                "server_ns",
                                server_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                            )

                            while True:
                                line = server_proc.stdout.readline()
                                if "SERVER_READY" in line:
                                    break
                                if server_proc.poll() is not None:
                                    print("Error: server failed to start", file=sys.stderr)
                                    break

                            tcpdump_cmd = [
                                "tcpdump",
                                "-i",
                                "veth_server",
                                "-w",
                                pcap_file,
                                "udp",
                                "port",
                                "4433",
                            ]
                            tcpdump_proc = run_cmd_ns(
                                "server_ns", tcpdump_cmd, stderr=subprocess.DEVNULL
                            )

                            time.sleep(0.5)

                            client_cmd = [
                                py_bin,
                                "quic_engine.py",
                                "client",
                                "--cipher",
                                cipher,
                                "--secrets-log",
                                secrets_file,
                            ]
                            client_proc = run_cmd_ns(
                                "client_ns",
                                client_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                            )

                            client_out, client_err = client_proc.communicate()

                            hct_ms = None
                            for line in client_out.splitlines():
                                if line.startswith("HCT_MS="):
                                    hct_ms = float(line.split("=")[1])

                            server_proc.send_signal(signal.SIGINT)
                            tcpdump_proc.send_signal(signal.SIGINT)
                            tcpdump_proc.wait()
                            server_proc.wait()

                            if hct_ms is None:
                                print(f"Handshake failed: {cipher}\n{client_err}", file=sys.stderr)
                            else:
                                print(f"  HCT: {hct_ms:.2f} ms")
                                try:
                                    import pyshark

                                    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
                                    client_bytes = server_bytes = client_pkts = server_pkts = 0
                                    for pkt in cap:
                                        if "IP" in pkt:
                                            length = int(pkt.length)
                                            if pkt.ip.src == "10.0.0.1":
                                                client_bytes += length
                                                client_pkts += 1
                                            elif pkt.ip.src == "10.0.0.2":
                                                server_bytes += length
                                                server_pkts += 1
                                    cap.close()
                                except ImportError:
                                    client_bytes = server_bytes = client_pkts = server_pkts = 0

                                writer.writerow(
                                    [
                                        run_id,
                                        cipher,
                                        rtt,
                                        loss,
                                        mtu,
                                        hct_ms,
                                        client_bytes,
                                        server_bytes,
                                        client_pkts,
                                        server_pkts,
                                    ]
                                )
                                f.flush()


if __name__ == "__main__":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("Error: root privileges required to manage netns and tcpdump")
    main()
