#!/usr/bin/env bash
set -euo pipefail

# End-to-end reproduction script for NL2026-0484 revision experiments.
# Requires root privileges for ip netns, tc netem, and tcpdump.

PY_BIN="${PY_BIN:-.venv/bin/python}"
if [ ! -x "${PY_BIN}" ]; then
    PY_BIN="$(command -v python3)"
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (e.g. sudo ./run_revision_benchmarks.sh)" >&2
    exit 1
fi

MODE="${1:-full}"  # 'verify', 'smoke', or 'full'

echo "[1/5] Running cryptographic & negative fault-injection verification..."
"${PY_BIN}" verify_mlkem_integration.py \
    --require-native-backend \
    --microbench 500 \
    --json-out results/crypto_verification.json

if [ "${MODE}" = "verify" ]; then
    echo "Verification-only run finished."
    exit 0
fi

echo "[2/5] Setting up isolated Linux network namespaces (client_ns <-> server_ns)..."
./netns_cleanup.sh || true
./netns_setup.sh

cleanup() {
    echo "[cleanup] Tearing down network namespaces..."
    ./netns_cleanup.sh || true
}
trap cleanup EXIT

echo "[3/5] Running QUIC + ML-KEM benchmark matrix (${MODE})..."
if [ "${MODE}" = "smoke" ]; then
    "${PY_BIN}" orchestrator.py --smoke-test --skip-verify
else
    "${PY_BIN}" orchestrator.py --skip-verify
fi

echo "[4/5] Generating figures and LaTeX tables from real PCAP & CSV telemetry..."
"${PY_BIN}" analyze_proofs.py --export-latex

if command -v pdflatex >/dev/null 2>&1; then
    echo "[5/5] Compiling LaTeX manuscript (main.tex)..."
    pdflatex -interaction=nonstopmode main.tex
    bibtex main || true
    pdflatex -interaction=nonstopmode main.tex
    pdflatex -interaction=nonstopmode main.tex
else
    echo "[5/5] pdflatex not found; generated tables in results/*.tex and figures in figures/*.png."
fi

echo "Revision benchmark pipeline completed cleanly."

