#!/usr/bin/env python3
import argparse
import asyncio
import logging
import ssl
import sys
import time

from aioquic.asyncio.client import connect
from aioquic.asyncio.server import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
import aioquic.tls

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

CIPHER_MAPPING = {
    "X25519": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
    "ML-KEM-512": "kyber512",
    "ML-KEM-768": "kyber768",
    "X25519-ML-KEM-768": "x25519_kyber768",
}

# (client_padding_bytes, server_padding_bytes) relative to classical baseline
CIPHER_PADDING = {
    "X25519": (0, 0),
    "ML-KEM-512": (800 - 32, 768 - 32),
    "ML-KEM-768": (1184 - 32, 1088 - 32),
    "X25519-ML-KEM-768": (1216 - 32, 1120 - 32),
}

# TLS extension 21 (Padding) hook to emulate FIPS 203 KeyShare and ciphertext sizes
original_push_client_hello = aioquic.tls.push_client_hello


def patched_push_client_hello(buf, hello):
    pad_size = getattr(aioquic.tls, "PQC_CLIENT_PADDING", 0)
    if pad_size > 0:
        hello.other_extensions.append((21, b"P" * pad_size))
    original_push_client_hello(buf, hello)


aioquic.tls.push_client_hello = patched_push_client_hello

original_push_server_hello = aioquic.tls.push_server_hello


def patched_push_server_hello(buf, hello):
    pad_size = getattr(aioquic.tls, "PQC_SERVER_PADDING", 0)
    if pad_size > 0:
        hello.other_extensions.append((21, b"P" * pad_size))
    original_push_server_hello(buf, hello)


aioquic.tls.push_server_hello = patched_push_server_hello


async def run_client(host: str, port: int, configuration: QuicConfiguration):
    start_time = time.time()
    try:
        async with connect(host, port, configuration=configuration) as client:
            hct = (time.time() - start_time) * 1000
            print(f"HCT_MS={hct:.2f}", flush=True)

            original_quic_event_received = client.quic_event_received

            def custom_event_received(event):
                if isinstance(event, StreamDataReceived) and event.end_stream:
                    print("ASSET_RECEIVED", flush=True)
                    client._quic.close(error_code=0)
                    client.transmit()
                original_quic_event_received(event)

            client.quic_event_received = custom_event_received

            stream_id = client._quic.get_next_available_stream_id(is_unidirectional=False)
            client._quic.send_stream_data(stream_id, b"GET /asset", end_stream=True)
            client.transmit()

            await client.wait_closed()

    except Exception as e:
        import traceback

        traceback.print_exc()
        print(f"CLIENT_ERROR: {e}", file=sys.stderr)
        sys.exit(1)


async def run_server(host: str, port: int, configuration: QuicConfiguration):
    def create_protocol(*args, **kwargs):
        from aioquic.asyncio.protocol import QuicConnectionProtocol

        class ServerProtocol(QuicConnectionProtocol):
            def quic_event_received(self, event):
                if isinstance(event, StreamDataReceived):
                    response_data = b"X" * 1024
                    self._quic.send_stream_data(event.stream_id, response_data, end_stream=True)
                    self.transmit()
                super().quic_event_received(event)

        return ServerProtocol(*args, **kwargs)

    await serve(host, port, configuration=configuration, create_protocol=create_protocol)
    print("SERVER_READY", flush=True)
    await asyncio.Future()


def main():
    parser = argparse.ArgumentParser(description="QUIC ML-KEM Benchmarking Engine")
    parser.add_argument("mode", choices=["client", "server"], help="Run as client or server")
    parser.add_argument("--host", type=str, default="10.0.0.2", help="Host IP")
    parser.add_argument("--port", type=int, default=4433, help="Port")
    parser.add_argument(
        "--cipher",
        type=str,
        default="X25519",
        choices=CIPHER_MAPPING.keys(),
        help="Cipher suite to use",
    )
    parser.add_argument(
        "--secrets-log",
        type=str,
        help="Log secrets to this file for Wireshark decryption",
    )
    args = parser.parse_args()

    configuration = QuicConfiguration(
        is_client=(args.mode == "client"),
        alpn_protocols=["hq-interop"],
        verify_mode=ssl.CERT_NONE if args.mode == "client" else None,
    )

    client_pad, server_pad = CIPHER_PADDING.get(args.cipher, (0, 0))
    aioquic.tls.PQC_CLIENT_PADDING = client_pad
    aioquic.tls.PQC_SERVER_PADDING = server_pad

    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")

    if args.mode == "server":
        configuration.load_cert_chain(certfile="tests/ssl_cert.pem", keyfile="tests/ssl_key.pem")
        try:
            asyncio.run(run_server(args.host, args.port, configuration))
        except KeyboardInterrupt:
            pass
    else:
        asyncio.run(run_client(args.host, args.port, configuration))


if __name__ == "__main__":
    main()
