# Quantifying Handshake Latency and Anti-Amplification Limits of Post-Quantum Key Encapsulation (ML-KEM) in QUIC over Degraded Networks

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.22879417-blue)](https://doi.org/10.5281/zenodo.22879417)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![RFC: 9000](https://img.shields.io/badge/RFC-9000%20Compliant-green.svg)](https://www.rfc-editor.org/rfc/rfc9000)

Reproducible systems testbed and telemetry artifacts for *IEEE Networking Letters* manuscript **NL2026-0484** (`v2.0.0`: genuine FIPS 203 `liboqs 0.12.0` integration).

## Key Architectural Revision (Post-Review Fix)
Following peer-review feedback (Reviewer 1), this testbed no longer uses TLS Extension 21 size padding. Instead, `mlkem_crypto.py` and `mlkem_tls.py` execute **authentic FIPS 203 ML-KEM cryptographic operations** inside the `aioquic` TLS 1.3 handshake state machine:
- **Client**: executes `ML-KEM.KeyGen` and serializes the genuine encapsulation key (`ek`) under IANA `key_share` group IDs (`0x0200` ML-KEM-512, `0x0201` ML-KEM-768, `0x11EC` RFC 10024 `X25519MLKEM768`).
- **Server**: parses the peer `key_share`, executes `ML-KEM.Encaps(ek)`, and returns the real ciphertext (`ct`) in `ServerHello`.
- **Client**: executes `ML-KEM.Decaps(dk, ct)` to recover the 32-byte ML-KEM shared secret.
- **TLS 1.3 Key Schedule Binding**: both endpoints inject the real ML-KEM shared secret (or concatenated `ss_mlkem || ss_x25519` for `X25519-ML-KEM-768`) into `aioquic.tls.KeySchedule.extract()` during Handshake Secret derivation (`generation == 1`). TLS `Finished` MACs and QUIC Handshake / 1-RTT packet protection keys depend causally on the post-quantum shared secret.

## Repository Layout
- `mlkem_crypto.py`: FIPS 203 (`liboqs-python`, `cryptography`, `kyber-py` fallback) primitives, wire-length checks, and nanosecond timing.
- `mlkem_tls.py`: Per-connection TLS 1.3 `ClientHello`/`ServerHello` `key_share` codec and `KeySchedule.extract` binding for `aioquic`.
- `quic_engine.py`: QUIC client/server binary enforcing real ML-KEM suites, verifying `GET /asset` payload delivery, and exposing `--tamper-ciphertext` fault injection.
- `verify_mlkem_integration.py`: Automated positive + negative cryptographic verification suite (round-trip sizes, shared-secret equality, keylog equality, 1-bit ciphertext-tamper rejection, anti-downgrade rejection, microbenchmarking).
- `pcap_utils.py`: Stdlib binary PCAP parser computing IP/UDP totals and RFC 9000 §8.1 pre-validation flights.
- `orchestrator.py`: Network-namespace orchestrator spanning 4 suites × 3 RTTs × 4 loss rates × 50 iterations (2,400 runs) with packet-buffered `tcpdump -U`.
- `analyze_proofs.py`: Generates CDF, anti-amplification, $p_{95}$ scaling, and crypto CPU breakdown plots plus `--export-latex` tables (`results/table_*.tex`).
- `Dockerfile` & `setup_env.sh`: Reproducible Ubuntu 24.04 environment with `liboqs 0.12.0`.
- `RESPONSE_TO_REVIEWERS.md`: Detailed point-by-point response and empirical validation summary (LaTeX manuscript sources are provided with the submission bundle).
- `replication_package/`: Self-contained replication mirror including verified `liboqs 0.12.0` captures in `sample_pcaps/` and 2,400-run telemetry in `results/`.

## Quick Verification (No Root Required)
Run positive handshake checks, negative 1-bit ciphertext tampering checks, anti-downgrade checks, and pure ML-KEM microbenchmarks over loopback UDP:

```bash
sudo ./setup_env.sh
.venv/bin/python verify_mlkem_integration.py --require-native-backend --microbench 500 --json-out results/crypto_verification.json
```

If C `liboqs` is not yet installed, you can verify functional cryptographic correctness using `kyber-py`:

```bash
python3 verify_mlkem_integration.py --microbench 20
```

## Full Linux Namespace Benchmarks & Manuscript Regeneration
Requires Linux kernel `ip netns`, `tc netem`, and root (or Docker with `--cap-add=NET_ADMIN`):

```bash
# 1. Verify + smoke test (2 iterations, 20ms, 0% loss)
sudo ./run_revision_benchmarks.sh smoke

# 2. Full 2,400-run evaluation + PCAP analysis + LaTeX table/figure export + PDF build
sudo ./run_revision_benchmarks.sh full
```

Or via Docker:

```bash
docker build -t quic-mlkem-bench .
docker run --rm -it --privileged -v "$(pwd)/results:/workspace/results" -v "$(pwd)/figures:/workspace/figures" quic-mlkem-bench ./run_revision_benchmarks.sh full
```

## Archival & Citation
The Zenodo concept DOI [`10.5281/zenodo.22879417`](https://doi.org/10.5281/zenodo.22879417) always resolves to the latest release (including `v2.0.0` with genuine FIPS 203 `liboqs` execution and negative fault-injection verification; prior initial release `v1.0.0` is archived at `10.5281/zenodo.22879418`).

```bibtex
@software{sudarsan_2026_quic_mlkem,
  author  = {Sudarsan, Potuganam},
  title   = {Quantifying Handshake Latency and Anti-Amplification Limits of Post-Quantum Key Encapsulation (ML-KEM) in QUIC over Degraded Networks},
  year    = {2026},
  doi     = {10.5281/zenodo.22879417},
  url     = {https://github.com/sudarsanSDA/quic-mlkem-benchmark}
}
```
