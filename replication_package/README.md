# Replication Package: QUIC ML-KEM Benchmarking

This package provides the scripts, telemetry dataset, and analysis routines to reproduce the findings in:
**"Quantifying Handshake Latency and Anti-Amplification Limits of Post-Quantum Key Encapsulation (ML-KEM) in QUIC over Degraded Networks"**

## System Prerequisites
- Operating System: Linux (Kernel 5.15+)
- Utilities: `iproute2`, `tcpdump`, `tshark`, `python3-pip`, `python3-venv`

## Contents
- `benchmark_results.csv`: Complete 2,400-iteration empirical dataset.
- `setup_env.sh`: Environment and dependency installation.
- `netns_setup.sh`: Network namespace and veth topology configuration.
- `netns_cleanup.sh`: Network namespace teardown.
- `apply_netem.sh`: Traffic control (tc netem) RTT, loss, and MTU configuration.
- `quic_engine.py`: QUIC wire-format emulation client and server.
- `orchestrator.py`: Automated benchmark testbed runner.
- `analyze_proofs.py`: Figure generation and anti-amplification analysis.
- `results/`: Empirical figures (Figure 1, Figure 2, Figure 3).
- `sample_pcaps/`: Curated packet captures and TLS key material.

## Execution
```bash
sudo ./setup_env.sh
sudo ./netns_setup.sh
sudo python3 orchestrator.py
python3 analyze_proofs.py
sudo ./netns_cleanup.sh
```
