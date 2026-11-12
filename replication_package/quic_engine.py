#!/usr/bin/env python3
"""QUIC + TLS 1.3 Post-Quantum Key Encapsulation (FIPS 203 ML-KEM) benchmark engine."""

import argparse
import asyncio
import logging
import ssl
import sys
import time
from typing import Dict

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived

from mlkem_crypto import normalize_suite_name, warmup_backend
import mlkem_tls

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

SUPPORTED_CIPHERS = ("X25519", "ML-KEM-512", "ML-KEM-768", "X25519-ML-KEM-768")
EXPECTED_ASSET = b"X" * 1024


async def run_client(
    host: str,
    port: int,
    configuration: QuicConfiguration,
    timeout_s: float = 15.0,
) -> int:
    """Connect to QUIC server, execute ML-KEM handshake, fetch and verify asset."""
    start_time = time.perf_counter()
    rx_streams: Dict[int, bytearray] = {}
    asset_verified = False

    async def _execute() -> None:
        nonlocal asset_verified
        async with connect(host, port, configuration=configuration) as client:
            hct_ms = (time.perf_counter() - start_time) * 1000.0
            state = mlkem_tls.get_connection_state(client._quic)

            original_quic_event_received = client.quic_event_received

            def custom_event_received(event):
                nonlocal asset_verified
                if isinstance(event, StreamDataReceived):
                    buf = rx_streams.setdefault(event.stream_id, bytearray())
                    buf.extend(event.data)
                    if event.end_stream:
                        payload = bytes(buf)
                        if payload == EXPECTED_ASSET:
                            asset_verified = True
                            print("ASSET_RECEIVED", flush=True)
                            print("ASSET_VERIFIED=1", flush=True)
                        else:
                            print(
                                f"ASSET_MISMATCH len={len(payload)}",
                                file=sys.stderr,
                                flush=True,
                            )
                        client._quic.close(error_code=0)
                        client.transmit()
                    return
                original_quic_event_received(event)

            client.quic_event_received = custom_event_received

            if state is not None:
                group_hex = (
                    f"0x{state.negotiated_group:04x}"
                    if state.negotiated_group is not None
                    else "0x0000"
                )
                print(f"HCT_MS={hct_ms:.3f}", flush=True)
                print(f"KEM_BACKEND={state.backend_used}", flush=True)
                print(f"NEGOTIATED_GROUP={group_hex}", flush=True)
                print(f"KEM_KEYGEN_MS={state.keygen_ms:.4f}", flush=True)
                print(f"KEM_DECAPS_MS={state.decaps_ms:.4f}", flush=True)
                print(f"KEM_SS_HASH={state.secret_sha256_prefix}", flush=True)
                print(f"KEM_MLKEM_HASH={state.mlkem_ss_sha256_prefix}", flush=True)
                print(
                    f"KEM_WIRE_SHARES=client:{state.client_share_bytes},server:{state.server_share_bytes}",
                    flush=True,
                )
                print(f"KEY_SCHEDULE_BOUND={int(state.key_schedule_bound)}", flush=True)
            else:
                print(f"HCT_MS={hct_ms:.3f}", flush=True)

            stream_id = client._quic.get_next_available_stream_id(is_unidirectional=False)
            client._quic.send_stream_data(stream_id, b"GET /asset", end_stream=True)
            client.transmit()

            await client.wait_closed()

    try:
        await asyncio.wait_for(_execute(), timeout=timeout_s)
    except asyncio.TimeoutError:
        print(f"CLIENT_ERROR: Handshake or asset fetch timed out after {timeout_s:.1f}s", file=sys.stderr)
        return 1
    except Exception as exc:
        import traceback

        traceback.print_exc()
        print(f"CLIENT_ERROR: {exc}", file=sys.stderr)
        return 1

    if not asset_verified:
        print("CLIENT_ERROR: Connection closed without verified asset payload", file=sys.stderr)
        return 1
    return 0


async def run_server(host: str, port: int, configuration: QuicConfiguration) -> None:
    """Serve QUIC connections with FIPS 203 ML-KEM key exchange."""

    def create_protocol(*args, **kwargs):
        class ServerProtocol(QuicConnectionProtocol):
            def __init__(self, *p_args, **p_kwargs):
                super().__init__(*p_args, **p_kwargs)
                self._rx_requests: Dict[int, bytearray] = {}
                self._handshake_logged = False

            def quic_event_received(self, event):
                if isinstance(event, HandshakeCompleted) and not self._handshake_logged:
                    self._handshake_logged = True
                    state = mlkem_tls.get_connection_state(self._quic)
                    if state is not None:
                        group_hex = (
                            f"0x{state.negotiated_group:04x}"
                            if state.negotiated_group is not None
                            else "0x0000"
                        )
                        print(
                            f"SERVER_HANDSHAKE suite={state.negotiated_suite} "
                            f"group={group_hex} backend={state.backend_used} "
                            f"encaps_ms={state.encaps_ms:.4f} ss_hash={state.secret_sha256_prefix}",
                            flush=True,
                        )
                elif isinstance(event, StreamDataReceived):
                    req_buf = self._rx_requests.setdefault(event.stream_id, bytearray())
                    req_buf.extend(event.data)
                    if event.end_stream:
                        self._quic.send_stream_data(
                            event.stream_id, EXPECTED_ASSET, end_stream=True
                        )
                        self.transmit()
                    return
                super().quic_event_received(event)

        return ServerProtocol(*args, **kwargs)

    await serve(host, port, configuration=configuration, create_protocol=create_protocol)
    print("SERVER_READY", flush=True)
    await asyncio.Future()


def main() -> None:
    parser = argparse.ArgumentParser(description="QUIC ML-KEM Benchmarking Engine")
    parser.add_argument("mode", choices=["client", "server"], help="Run as client or server")
    parser.add_argument("--host", type=str, default="10.0.0.2", help="Host IP")
    parser.add_argument("--port", type=int, default=4433, help="Port")
    parser.add_argument(
        "--cipher",
        type=str,
        default="X25519",
        choices=SUPPORTED_CIPHERS,
        help="Key exchange suite to enforce",
    )
    parser.add_argument(
        "--backend",
        type=str,
        default=None,
        choices=["liboqs", "cryptography", "kyber_py"],
        help="Optional explicit FIPS 203 backend (defaults to auto: liboqs -> cryptography -> kyber_py)",
    )
    parser.add_argument(
        "--tamper-ciphertext",
        action="store_true",
        help="Flip 1 bit in ServerHello ML-KEM ciphertext on wire (fault-injection validation)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Client handshake + transfer timeout in seconds",
    )
    parser.add_argument(
        "--certfile",
        type=str,
        default="tests/ssl_cert.pem",
        help="Server TLS certificate PEM path",
    )
    parser.add_argument(
        "--keyfile",
        type=str,
        default="tests/ssl_key.pem",
        help="Server TLS private key PEM path",
    )
    parser.add_argument(
        "--secrets-log",
        type=str,
        help="Log TLS secrets to SSLKEYLOGFILE path for Wireshark / verification",
    )
    args = parser.parse_args()

    mlkem_tls.install_mlkem_tls()
    suite = normalize_suite_name(args.cipher)

    configuration = QuicConfiguration(
        is_client=(args.mode == "client"),
        alpn_protocols=["hq-interop"],
        verify_mode=ssl.CERT_NONE if args.mode == "client" else None,
    )
    mlkem_tls.configure_mlkem_suite(
        configuration,
        suite,
        backend=args.backend,
        tamper_ciphertext=args.tamper_ciphertext,
    )
    warmup_backend(suite, backend=args.backend)

    secrets_handle = None
    if args.secrets_log:
        secrets_handle = open(args.secrets_log, "a", encoding="utf-8")
        configuration.secrets_log_file = secrets_handle

    try:
        if args.mode == "server":
            configuration.load_cert_chain(certfile=args.certfile, keyfile=args.keyfile)
            try:
                asyncio.run(run_server(args.host, args.port, configuration))
            except KeyboardInterrupt:
                pass
        else:
            rc = asyncio.run(
                run_client(args.host, args.port, configuration, timeout_s=args.timeout)
            )
            sys.exit(rc)
    finally:
        if secrets_handle is not None:
            secrets_handle.close()


if __name__ == "__main__":
    main()
