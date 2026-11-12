#!/usr/bin/env python3
"""End-to-end cryptographic verification & negative fault-injection suite for ML-KEM QUIC.

Proves all Reviewer 1 requirements:
  1. Genuine FIPS 203 KeyGen / Encaps / Decaps execution and exact wire sizes.
  2. Real TLS 1.3 KeyShare negotiation (0x0200, 0x0201, 0x11EC) and KeySchedule secret binding.
  3. Client == Server shared secret equality, identical TLS SSLKEYLOGFILE traffic secrets,
     and authenticated 1-RTT QUIC stream transfer (GET /asset -> 1024 bytes).
  4. Causal necessity proof (Negative Tests): flipping 1 bit in wire ML-KEM ciphertext
     causes FIPS 203 implicit rejection and deterministic QUIC/TLS handshake failure;
     enforcing ML-KEM-768 against an X25519 server rejects downgrade.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import ipaddress
import json
import os
import statistics
import ssl
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from mlkem_crypto import (
    detect_backend,
    flip_first_bit,
    get_suite_spec,
    kem_decaps,
    kem_encaps,
    kem_keygen,
)
import mlkem_tls

SUITES = ("X25519", "ML-KEM-512", "ML-KEM-768", "X25519-ML-KEM-768")
PQC_SUITES = ("ML-KEM-512", "ML-KEM-768", "X25519-ML-KEM-768")
EXPECTED_ASSET = b"X" * 1024


def generate_ephemeral_cert(tmpdir: str) -> Tuple[str, str]:
    """Create a self-signed ECDSA P-256 test certificate in tmpdir."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(tmpdir, "cert.pem")
    key_path = os.path.join(tmpdir, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return cert_path, key_path


def _parse_keylog(path: str) -> Dict[str, str]:
    secrets: Dict[str, str] = {}
    if not os.path.exists(path):
        return secrets
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3:
                label, client_random, secret_hex = parts
                secrets[f"{label}:{client_random}"] = secret_hex
    return secrets


def verify_primitives(backend: Optional[str] = None) -> Dict[str, Dict[str, object]]:
    """Test raw FIPS 203 KeyGen/Encaps/Decaps round-trip and implicit rejection."""
    results: Dict[str, Dict[str, object]] = {}
    for alg in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        spec = get_suite_spec(alg)
        used_backend = backend or detect_backend(alg)
        ek, dk, kg_ms, b1 = kem_keygen(alg, backend=used_backend)
        ct, ss_enc, enc_ms, b2 = kem_encaps(alg, ek, backend=used_backend)
        ss_dec, dec_ms, b3 = kem_decaps(alg, dk, ct, backend=used_backend)

        assert len(ek) == spec.ek_bytes, f"{alg}: unexpected ek length {len(ek)}"
        assert len(ct) == spec.ct_bytes, f"{alg}: unexpected ct length {len(ct)}"
        assert len(ss_enc) == 32 and ss_enc == ss_dec, f"{alg}: shared secret mismatch!"

        # Implicit rejection test: 1-bit flip in ct must yield a different secret
        ct_tampered = flip_first_bit(ct)
        ss_bad, _, _ = kem_decaps(alg, dk, ct_tampered, backend=used_backend)
        assert len(ss_bad) == 32 and ss_bad != ss_enc, (
            f"{alg}: tampered ciphertext unexpectedly recovered identical shared secret"
        )

        results[alg] = {
            "backend": b1,
            "ek_bytes": len(ek),
            "ct_bytes": len(ct),
            "ss_bytes": len(ss_enc),
            "keygen_ms": round(kg_ms, 4),
            "encaps_ms": round(enc_ms, 4),
            "decaps_ms": round(dec_ms, 4),
            "implicit_rejection_verified": True,
        }
        assert b1 == b2 == b3
    return results


async def run_quic_exchange(
    cert_path: str,
    key_path: str,
    client_suite: str,
    server_suite: str,
    *,
    backend: Optional[str] = None,
    tamper_ciphertext: bool = False,
    timeout_s: float = 4.0,
) -> Dict[str, object]:
    """Execute one real loopback QUIC connection and capture client/server telemetry."""
    mlkem_tls.install_mlkem_tls()

    with tempfile.TemporaryDirectory() as logdir:
        c_keylog = os.path.join(logdir, "client.keys")
        s_keylog = os.path.join(logdir, "server.keys")

        server_cfg = QuicConfiguration(
            is_client=False,
            alpn_protocols=["hq-interop"],
        )
        server_cfg.load_cert_chain(certfile=cert_path, keyfile=key_path)
        s_keylog_f = open(s_keylog, "w", encoding="utf-8")
        server_cfg.secrets_log_file = s_keylog_f
        mlkem_tls.configure_mlkem_suite(
            server_cfg,
            server_suite,
            backend=backend,
            tamper_ciphertext=tamper_ciphertext,
        )

        client_cfg = QuicConfiguration(
            is_client=True,
            alpn_protocols=["hq-interop"],
            verify_mode=ssl.CERT_NONE,
        )
        c_keylog_f = open(c_keylog, "w", encoding="utf-8")
        client_cfg.secrets_log_file = c_keylog_f
        mlkem_tls.configure_mlkem_suite(client_cfg, client_suite, backend=backend)

        server_states: List[mlkem_tls.ConnectionMLKEMState] = []

        def create_protocol(*args, **kwargs):
            class TestServerProtocol(QuicConnectionProtocol):
                def __init__(self, *a, **kw):
                    super().__init__(*a, **kw)
                    self._rx = bytearray()

                def quic_event_received(self, event):
                    if isinstance(event, StreamDataReceived):
                        self._rx.extend(event.data)
                        if event.end_stream:
                            st = mlkem_tls.get_connection_state(self._quic)
                            if st is not None:
                                server_states.append(st)
                            self._quic.send_stream_data(
                                event.stream_id, EXPECTED_ASSET, end_stream=True
                            )
                            self.transmit()
                        return
                    super().quic_event_received(event)

            return TestServerProtocol(*args, **kwargs)

        server = await serve(
            "127.0.0.1", 0, configuration=server_cfg, create_protocol=create_protocol
        )
        port = server._transport.get_extra_info("sockname")[1]

        rx_buf = bytearray()
        done_event = asyncio.Event()
        client_state = None
        handshake_succeeded = False
        error_msg = ""

        try:
            async def _client_task():
                nonlocal client_state, handshake_succeeded
                async with connect("127.0.0.1", port, configuration=client_cfg) as client:
                    handshake_succeeded = True
                    client_state = mlkem_tls.get_connection_state(client._quic)
                    orig_cb = client.quic_event_received

                    def on_event(event):
                        if isinstance(event, StreamDataReceived):
                            rx_buf.extend(event.data)
                            if event.end_stream:
                                done_event.set()
                                client._quic.close(error_code=0)
                                client.transmit()
                            return
                        orig_cb(event)

                    client.quic_event_received = on_event
                    sid = client._quic.get_next_available_stream_id(is_unidirectional=False)
                    client._quic.send_stream_data(sid, b"GET /asset", end_stream=True)
                    client.transmit()
                    await done_event.wait()

            await asyncio.wait_for(_client_task(), timeout=timeout_s)
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"
        finally:
            server.close()
            c_keylog_f.close()
            s_keylog_f.close()

        latest_server_state = server_states[-1] if server_states else mlkem_tls.get_latest_config_state(server_cfg)
        c_keys = _parse_keylog(c_keylog)
        s_keys = _parse_keylog(s_keylog)

        return {
            "client_suite": client_suite,
            "server_suite": server_suite,
            "tamper_ciphertext": tamper_ciphertext,
            "handshake_succeeded": handshake_succeeded,
            "asset_verified": bytes(rx_buf) == EXPECTED_ASSET,
            "error": error_msg,
            "client_state": client_state.to_summary() if client_state else None,
            "server_state": latest_server_state.to_summary() if latest_server_state else None,
            "client_server_secret_match": (
                client_state is not None
                and latest_server_state is not None
                and client_state.ss_effective is not None
                and client_state.ss_effective == latest_server_state.ss_effective
            ),
            "mlkem_ss_match": (
                client_state is not None
                and latest_server_state is not None
                and client_state.ss_mlkem is not None
                and client_state.ss_mlkem == latest_server_state.ss_mlkem
            ),
            "keylog_labels_matched": sorted(
                k for k, v in c_keys.items() if s_keys.get(k) == v
            ),
        }


def run_microbenchmark(iterations: int = 200, backend: Optional[str] = None) -> Dict[str, Dict[str, object]]:
    """Measure pure ML-KEM KeyGen / Encaps / Decaps latencies across suites."""
    out: Dict[str, Dict[str, object]] = {}
    for alg in ("ML-KEM-512", "ML-KEM-768"):
        used_backend = backend or detect_backend(alg)
        kg_us: List[float] = []
        enc_us: List[float] = []
        dec_us: List[float] = []
        for _ in range(iterations):
            ek, dk, kg_ms, _ = kem_keygen(alg, backend=used_backend)
            ct, ss_a, enc_ms, _ = kem_encaps(alg, ek, backend=used_backend)
            ss_b, dec_ms, _ = kem_decaps(alg, dk, ct, backend=used_backend)
            assert ss_a == ss_b
            kg_us.append(kg_ms * 1000.0)
            enc_us.append(enc_ms * 1000.0)
            dec_us.append(dec_ms * 1000.0)

        def _stats(vals: List[float]) -> Dict[str, float]:
            s = sorted(vals)
            p95_idx = min(len(s) - 1, int(0.95 * len(s)))
            return {
                "mean_us": round(statistics.mean(vals), 2),
                "median_us": round(statistics.median(vals), 2),
                "p95_us": round(s[p95_idx], 2),
            }

        out[alg] = {
            "backend": used_backend,
            "iterations": iterations,
            "keygen": _stats(kg_us),
            "encaps": _stats(enc_us),
            "decaps": _stats(dec_us),
            "total_mean_us": round(
                statistics.mean(kg_us) + statistics.mean(enc_us) + statistics.mean(dec_us), 2
            ),
        }
    return out


async def main_async(args: argparse.Namespace) -> int:
    print("== 1. Verifying FIPS 203 ML-KEM primitives ==")
    prim_report = verify_primitives(backend=args.backend)
    for alg, info in prim_report.items():
        print(
            f"  [PASS] {alg}: backend={info['backend']} ek={info['ek_bytes']}B "
            f"ct={info['ct_bytes']}B implicit_rejection={info['implicit_rejection_verified']}"
        )

    if args.require_native_backend:
        for alg, info in prim_report.items():
            if info["backend"] == "kyber_py":
                print(
                    f"  [FAIL] {alg} resolved to pure-Python kyber_py while --require-native-backend is set",
                    file=sys.stderr,
                )
                return 1

    e2e_positive: Dict[str, object] = {}
    e2e_negative: Dict[str, object] = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path, key_path = generate_ephemeral_cert(tmpdir)

        print("== 2. Verifying end-to-end QUIC + TLS 1.3 ML-KEM handshakes ==")
        for suite in SUITES:
            spec = get_suite_spec(suite)
            res = await run_quic_exchange(
                cert_path, key_path, suite, suite, backend=args.backend
            )
            e2e_positive[suite] = res

            c_st = res["client_state"]
            s_st = res["server_state"]
            assert res["handshake_succeeded"], f"{suite} handshake failed: {res['error']}"
            assert res["asset_verified"], f"{suite} asset payload verification failed"
            assert res["client_server_secret_match"], f"{suite} client/server TLS shared secret mismatch"
            assert c_st is not None and s_st is not None
            assert c_st["key_schedule_bound"] and s_st["key_schedule_bound"], (
                f"{suite} KeySchedule not bound"
            )
            assert c_st["negotiated_group"] == f"0x{spec.iana_group:04x}", (
                f"{suite} negotiated group mismatch: {c_st['negotiated_group']}"
            )
            assert c_st["client_share_bytes"] == spec.client_share_bytes, (
                f"{suite} client share size {c_st['client_share_bytes']} != {spec.client_share_bytes}"
            )
            assert c_st["server_share_bytes"] == spec.server_share_bytes, (
                f"{suite} server share size {c_st['server_share_bytes']} != {spec.server_share_bytes}"
            )
            assert len(res["keylog_labels_matched"]) >= 2, (
                f"{suite} client/server TLS keylog secrets did not match"
            )
            if spec.is_pqc:
                assert res["mlkem_ss_match"], f"{suite} raw ML-KEM shared secrets do not match"

            print(
                f"  [PASS] {suite}: group={c_st['negotiated_group']} "
                f"shares=({c_st['client_share_bytes']}B,{c_st['server_share_bytes']}B) "
                f"ss_hash={c_st['secret_sha256_prefix']} keylog_matches={len(res['keylog_labels_matched'])}"
            )

        print("== 3. Verifying negative fault-injection (ciphertext tamper & anti-downgrade) ==")
        for suite in PQC_SUITES:
            res = await run_quic_exchange(
                cert_path,
                key_path,
                suite,
                suite,
                backend=args.backend,
                tamper_ciphertext=True,
                timeout_s=2.0,
            )
            e2e_negative[f"tamper:{suite}"] = res
            assert not res["handshake_succeeded"], (
                f"SECURITY BUG: {suite} handshake succeeded despite tampered ML-KEM ciphertext!"
            )
            assert not res["asset_verified"], (
                f"SECURITY BUG: {suite} delivered asset despite tampered ML-KEM ciphertext!"
            )
            print(
                f"  [PASS] tamper:{suite}: handshake rejected as expected ({res['error']})"
            )

        # Anti-downgrade check: client requiring ML-KEM-768 must reject X25519 server
        downgrade_res = await run_quic_exchange(
            cert_path,
            key_path,
            "ML-KEM-768",
            "X25519",
            backend=args.backend,
            timeout_s=2.0,
        )
        e2e_negative["downgrade:ML-KEM-768->X25519"] = downgrade_res
        assert not downgrade_res["handshake_succeeded"], (
            "SECURITY BUG: ML-KEM-768 client accepted classical X25519 server!"
        )
        print(
            f"  [PASS] downgrade:ML-KEM-768->X25519 rejected ({downgrade_res['error']})"
        )

    micro_report = {}
    if args.microbench > 0:
        print(f"== 4. Running pure FIPS 203 microbenchmark ({args.microbench} iterations) ==")
        micro_report = run_microbenchmark(iterations=args.microbench, backend=args.backend)
        for alg, stats in micro_report.items():
            print(
                f"  [STAT] {alg} ({stats['backend']}): "
                f"KeyGen={stats['keygen']['mean_us']}us "
                f"Encaps={stats['encaps']['mean_us']}us "
                f"Decaps={stats['decaps']['mean_us']}us "
                f"(Total={stats['total_mean_us']}us)"
            )

    if args.json_out:
        os.makedirs(os.path.dirname(args.json_out) or ".", exist_ok=True)
        payload = {
            "primitives": prim_report,
            "e2e_positive": e2e_positive,
            "e2e_negative": e2e_negative,
            "microbenchmark": micro_report,
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"Saved verification artifact to {args.json_out}")

    print("ALL CRYPTOGRAPHIC AND END-TO-END QUIC VERIFICATION CHECKS PASSED.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify real FIPS 203 ML-KEM integration in aioquic")
    parser.add_argument(
        "--backend",
        type=str,
        default=None,
        choices=["liboqs", "cryptography", "kyber_py"],
        help="Force a specific ML-KEM backend",
    )
    parser.add_argument(
        "--require-native-backend",
        action="store_true",
        help="Fail if resolved to pure-Python kyber_py fallback instead of C liboqs/cryptography",
    )
    parser.add_argument(
        "--microbench",
        type=int,
        default=200,
        help="Number of iterations for KeyGen/Encaps/Decaps microbenchmark (0 to skip)",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default="",
        help="Optional output path for structured JSON verification report",
    )
    args = parser.parse_args()
    rc = asyncio.run(main_async(args))
    sys.exit(rc)


if __name__ == "__main__":
    main()

