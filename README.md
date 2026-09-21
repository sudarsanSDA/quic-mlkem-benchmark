# Quantifying Handshake Latency and Anti-Amplification Limits of Post-Quantum Key Encapsulation (ML-KEM) in QUIC over Degraded Networks

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.22878525-blue)](https://doi.org/10.5281/zenodo.22878525)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![RFC: 9000](https://img.shields.io/badge/RFC-9000%20Compliant-green.svg)](https://www.rfc-editor.org/rfc/rfc9000)

This repository contains the empirical benchmarking testbed, telemetry datasets, and replication package for evaluating NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) in QUIC (RFC 9000 / RFC 9001) across degraded network environments.

## Overview

The empirical evaluation investigates the transport-layer implications of deploying post-quantum key encapsulation mechanisms (ML-KEM-512, ML-KEM-768, and hybrid X25519-ML-KEM-768) compared to classical X25519 in QUIC. Across 2,400 bare-metal network namespace benchmark runs spanning varying round-trip times (20ms, 80ms, 160ms) and packet loss rates (0%, 1%, 3%, 5%), two primary systems phenomena were identified:

1. **KEM Amplification Paradox**: RFC 9000 §8.1 limits an unvalidated server to sending at most 3x the bytes received from the client. Because ML-KEM-768 requires an 1,184-byte public key share, the client's initial flight expands across multiple datagrams (~2,484 bytes). This grants the server up to 7,452 bytes of credit before address validation, eliminating server-side anti-amplification stalls for pure KEM handshakes.
2. **Client-Side Fragmentation Fragility**: When the enlarged ClientHello spans two UDP datagrams, loss of either packet under lossy conditions (1% to 5%) prevents server-side KeyShare reconstruction. This triggers client loss recovery and idle timer delays, causing tail latency ($p_{95}$/$p_{99}$) to increase by 34% compared to classical handshakes under identical channel degradation.

## Repository Structure

```
.
|-- .gitignore
|-- README.md
|-- LICENSE
|-- benchmark_results.csv
|-- generate_summary.py
|-- setup_env.sh
|-- netns_setup.sh
|-- netns_cleanup.sh
|-- apply_netem.sh
|-- quic_engine.py
|-- orchestrator.py
|-- analyze_proofs.py
|-- results/
|   |-- fig1_cdf_hct_3loss.png
|   |-- fig2_anti_amplification.png
|   |-- fig3_latency_scaling.png
`-- replication_package/
    |-- README.md
    |-- benchmark_results.csv
    |-- setup_env.sh
    |-- netns_setup.sh
    |-- netns_cleanup.sh
    |-- apply_netem.sh
    |-- quic_engine.py
    |-- orchestrator.py
    |-- analyze_proofs.py
    |-- results/
    `-- sample_pcaps/
        |-- ML-KEM-768_20_0_2.pcap
        |-- ML-KEM-768_20_3_41.pcap
        |-- X25519_20_3_0.keys
        `-- X25519_20_3_0.pcap
```

## Reproduction Guide

### System Prerequisites
- Linux Kernel: 5.15 or newer
- Kernel modules: `sch_netem`, `veth`
- System packages: `iproute2`, `tcpdump`, `tshark`, `python3-pip`, `python3-venv`, `libssl-dev`
- Python: 3.10+

### Setup and Execution

1. **Install dependencies and create virtual environment**:
   ```bash
   sudo ./setup_env.sh
   source venv/bin/activate
   ```

2. **Configure network namespaces**:
   ```bash
   sudo ./netns_setup.sh
   ```

3. **Run benchmark matrix**:
   ```bash
   # Run full 2,400 iteration matrix
   sudo python3 orchestrator.py

   # Or run smoke test (1 iteration, 2 ciphers)
   sudo python3 orchestrator.py --smoke-test
   ```

4. **Generate analysis and figures**:
   ```bash
   python3 analyze_proofs.py
   ```

5. **Clean up network namespaces**:
   ```bash
   sudo ./netns_cleanup.sh
   ```

## Citation

```bibtex
@article{sudarsan2026quicmlkem,
  author = {Sudarsan, P.},
  title = {Quantifying Handshake Latency and Anti-Amplification Limits of Post-Quantum Key Encapsulation (ML-KEM) in QUIC over Degraded Networks},
  year = {2026},
  doi = {10.5281/zenodo.22878525}
}
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
