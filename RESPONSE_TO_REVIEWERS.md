# Point-by-Point Response to Reviewers — IEEE Networking Letters (NL2026-0484)

**Manuscript Title:** *Quantifying Handshake Latency and Anti-Amplification Limits of Post-Quantum Key Encapsulation (ML-KEM) in QUIC over Degraded Networks*

We sincerely thank the Editorial Office and Reviewers 1 and 2 for their constructive, insightful feedback. Every raised limitation has been addressed directly in the codebase, verification suite, reproducibility infrastructure, and revised manuscript (`main.tex`), as detailed below.

> **Execution & Validation Summary (Ubuntu 24.04 Linux VM, ARM Neoverse-N1, `liboqs 0.12.0`):** All real FIPS 203 ML-KEM cryptography (`KeyGen`, `Encaps`, `Decaps`), TLS 1.3 `KeySchedule` secret binding, positive end-to-end QUIC tests, negative fault-injection (`--tamper-ciphertext` and anti-downgrade), 500-iteration C microbenchmarks (`172.3 us` for ML-KEM-512, `246.5 us` for ML-KEM-768), and the full **2,400-run** Linux network-namespace (`ip netns` + `tc netem` + `tcpdump`) matrix have been executed to completion cleanly (`2,400 / 2,400` `Secret_Match = 1` and `Asset_Verified = 1`, `0` anti-amplification violations), and all plots, LaTeX tables/macros, and `main.pdf` are compiled and synchronized.

---

## Response to Reviewer 1

> **Reviewer 1 Comment:** *The experiments rely on emulating the sizes of ML-KEM messages rather than executing the actual cryptographic operations. To demonstrate an effective integration of ML-KEM into TLS/QUIC, the authors need to implement and verify the complete process, including encapsulation and decapsulation of the shared secret, and confirm its role in establishing the connection. Emulating message sizes does not demonstrate that this integration actually works. Therefore, I consider this limitation to significantly affect the contribution of the work and to require additional experimental validation.*

### Changes Implemented
1. **Replaced TLS Extension 21 Size Padding with Real FIPS 203 ML-KEM Cryptography (`mlkem_crypto.py`, `mlkem_tls.py`, `quic_engine.py`):**
   - Removed the prior `CIPHER_PADDING` / TLS Extension 21 hook completely.
   - Implemented real `KeyGen`, `Encaps`, and `Decaps` for NIST FIPS 203 `ML-KEM-512` (800 B `ek`, 768 B `ct`), `ML-KEM-768` (1,184 B `ek`, 1,088 B `ct`), and RFC 10024 hybrid `X25519-ML-KEM-768` (1,216 B client share, 1,120 B server share, 64 B combined secret) backed by Open Quantum Safe `liboqs` (`0.12.0` C library via `liboqs-python`), with `cryptography.hazmat.primitives.asymmetric.mlkem` and `kyber-py` functional support.
2. **Authentic Wire Negotiation & TLS 1.3 Key Schedule Binding (`mlkem_tls.py`):**
   - `ClientHello` and `ServerHello` serialize genuine IANA `key_share` (`0x0033`) and `supported_groups` (`0x000A`) code points (`0x0200` MLKEM512, `0x0201` MLKEM768, `0x11EC` X25519MLKEM768) containing the actual `ek` and `ct` bytes, ensuring both endpoints hash the true ML-KEM payloads into the TLS 1.3 handshake transcript (`key_schedule.hash`).
   - Intercepted `aioquic.tls.KeySchedule.extract()` at Handshake Secret generation (`generation == 1`) so that the derived ML-KEM shared secret `ss_mlkem` (32 B) — or RFC 10024 concatenation `ss_mlkem || ss_x25519` (64 B) — directly drives TLS `Handshake Traffic Secrets`, `Finished` MAC verification, and QUIC Handshake / 1-RTT AEAD encryption keys.
3. **End-to-End Positive & Negative Fault-Injection Verification (`verify_mlkem_integration.py`):**
   - **Positive proofs:** Tests real UDP QUIC handshakes across all 4 suites, asserting IANA group negotiation, wire share lengths, `client_ss_mlkem == server_ss_mlkem`, identical client/server `SSLKEYLOGFILE` secrets, and verified 1,024-byte 1-RTT payload transfer (`GET /asset`).
   - **Negative causality proof (`--tamper-ciphertext`):** Flips 1 bit of the wire ML-KEM ciphertext inside `ServerHello`, proving that FIPS 203 implicit rejection yields mismatched secrets and causes deterministic TLS/QUIC handshake failure and zero application data transfer. Also verifies anti-downgrade rejection against classical servers when ML-KEM is required.
4. **Telemetry Repairs, Classical Baseline & Full 2,400-Run Matrix (`pcap_utils.py`, `orchestrator.py`, `analyze_proofs.py`):**
   - Fixed `tcpdump` capture buffering (`-U -n -s 0` with clean drain delay), replaced `pyshark` calls with direct RFC 9000 binary PCAP parsing (`pcap_utils.py`), and instrumented classical X25519 (0.051 ms KeyGen, 0.135 ms ECDH derivation; 0.186 ms total) to ensure fair CPU comparisons against KEM suites.
   - Disaggregated Flight 1 Initial datagrams (2 pkts, 2,400 B; $1-(1-p)^2 = 5.91\%$ at 3% loss) from cumulative pre-validation (3 pkts, 3,600 B; $1-(1-p)^3 = 8.73\%$), and logged per-run `KeyGen`, `Encaps`, `Decaps`, and `Secret_Match` across all 2,400 runs.
   - Revised Section III, Section IV, and Section V of `main.tex` to report verified real-crypto data, bootstrap quantile bounds, and CPU vs. transport latency separation.

---

## Response to Reviewer 2

> **Reviewer 2 Comment 1:** *First, there are already several studies evaluating PQC in QUIC. The authors should clarify how their work differs from existing studies and what new insights it provides.*

### Changes Implemented
- Added **Section II-A (*Comparison with Prior PQC Studies and Novelty*)** and comparative **Table I (`\label{tab:novelty}`)** in `main.tex`, explicitly positioning our study against Paquin et al. (PQCrypto 2020), Sikeridis et al. (NDSS 2020), Schwabe et al. (CCS 2020 KEMTLS), Kempf et al. (IFIP Networking 2024), Wolsing et al. (ANRW 2019), RFC 10024 (2026), Rigon et al. (IEEE CNS 2025), and Montenegro et al. (Computer Networks 2026).
- Articulated three distinct new insights:
  1. **Pre-Validation Credit Inversion:** Rather than exhausting a 3,600 B server cap, client-side ML-KEM key shares expand Flight 1 credit to 7,200 B (10,800 B cumulative), providing headroom against post-quantum certificate stalls while baseline minimal flights (2,581 B) remain unblocked.
  2. **Bottleneck Shift to Client Initial Fragility:** When server anti-amplification remains satisfied, the performance limiter moves to client-side two-datagram Initial packet loss exposure ($1 - (1-p)^2 = 5.91\%$ at 3% loss; 8.73% across all 3 pre-validation datagrams), driving RTT-scale PTO recovery delays.
  3. **Verified Crypto-to-Transport Disaggregation:** Separating C-backed FIPS 203 compute time from multi-hundred-millisecond tail latency, causally validated through ciphertext-tamper fault injection.

> **Reviewer 2 Comment 2:** *Second, Equation (1) lacks sufficient explanation and an appropriate citation, making it unclear where the equation originates.*

### Changes Implemented
- Revised **Section II-B (*QUIC Anti-Amplification Invariant (RFC 9000)*)** and **Equation (1)** in `main.tex`:
  - Added direct inline attribution `\cite[Sec.~8.1]{rfc9000}` alongside Equation (1) and explanatory citations to RFC 9000 Sections 8.1 and 14.1 (`\cite{rfc9000}`).
  - Formally defined both equation terms ($\mathrm{Bytes}_{\mathrm{Server}}$ as cumulative UDP payload bytes sent by the server to an unvalidated peer address before validation completes; $\mathrm{Bytes}_{\mathrm{Client,Received}}$ as cumulative authentic UDP datagram bytes received from the client across Initial packets).
  - Explained the UDP IP-spoofing reflection DDoS threat model, the RFC 9000 Section 14.1 1,200-byte minimum Initial datagram requirement (yielding the 3,600-byte classical budget), exact address-validation termination triggers (receipt of an authenticated client `Handshake` packet or `Retry` token), and server transmission stall behavior upon budget exhaustion.

---

## Reproducibility & Format Compliance (`Dockerfile`, `setup_env.sh`, `run_revision_benchmarks.sh`)
In line with Reviewer 2's positive note on reproducibility and *IEEE Networking Letters* formatting guidelines, we strictly adhere to the **4-page double-column IEEE template** (`main.tex` / `main.pdf`), maintain full author naming without unrequested declarations sections, provide the updated resubmission Cover Letter (`cover_letter.tex` / `cover_letter.pdf`, referencing prior ID **NL2026-0484**), added the previously missing `Dockerfile`, updated `setup_env.sh` to build shared `liboqs 0.12.0` + `liboqs-python` inside an isolated virtual environment, synchronized `replication_package/`, and added `run_revision_benchmarks.sh` to automate full verification, Linux namespace measurements, plot rendering, LaTeX table export, and manuscript compilation.

All updated code modules (`mlkem_crypto.py`, `mlkem_tls.py`, `verify_mlkem_integration.py`, `pcap_utils.py`, `run_revision_benchmarks.sh`), verified captures (`replication_package/sample_pcaps/`), and 2,400-run telemetry are published at [GitHub](https://github.com/sudarsanSDA/quic-mlkem-benchmark) and Zenodo under concept DOI [`10.5281/zenodo.22879417`](https://doi.org/10.5281/zenodo.22879417) (v2.1.0 release: [`10.5281/zenodo.24154361`](https://doi.org/10.5281/zenodo.24154361)).

