"""Real FIPS 203 ML-KEM and RFC 10024 X25519MLKEM768 integration for aioquic TLS 1.3.

Unlike TLS padding emulation, this module:
  1. Serializes genuine IANA KeyShare group IDs (0x0200 ML-KEM-512, 0x0201 ML-KEM-768,
     0x11EC X25519MLKEM768) carrying real FIPS 203 encapsulation keys (ek) and ciphertexts (ct)
     inside TLS 1.3 ClientHello and ServerHello wire messages so the TLS transcript hash
     binds the authentic ML-KEM handshake messages.
  2. Executes real ML-KEM KeyGen (client), Encaps (server), and Decaps (client).
  3. Injects the derived ML-KEM shared secret (or concatenated ML-KEM || X25519 secret for
     hybrid X25519MLKEM768) into ``aioquic.tls.KeySchedule.extract`` during TLS Handshake Secret
     derivation (generation == 1), ensuring TLS Finished MACs and QUIC Handshake / 1-RTT AEAD
     keys depend cryptographically on the post-quantum shared secret.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
import functools
import struct
from typing import Dict, List, Optional, Tuple
import weakref

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import aioquic.buffer
import aioquic.quic.configuration
import aioquic.quic.connection
import aioquic.tls

from mlkem_crypto import (
    GROUP_TO_SUITE,
    IANA_GROUP_X25519,
    get_suite_spec,
    flip_first_bit,
    kem_decaps,
    kem_encaps,
    kem_keygen,
    normalize_suite_name,
    secret_fingerprint,
    split_hybrid_client_share,
    split_hybrid_server_share,
)

EXT_SUPPORTED_GROUPS = 0x000A
EXT_KEY_SHARE = 0x0033

# RFC 8446 Section 4.1.3 HelloRetryRequest special random constant
_HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

# Valid Curve25519 point used solely to keep aioquic's internal ECDH state machine satisfied
# during pure ML-KEM suites; its secret is discarded when KeySchedule.extract binds ss_mlkem.
_DUMMY_X25519_PUB = X25519PrivateKey.generate().public_key().public_bytes_raw()


@dataclass(frozen=True)
class MLKEMPolicy:
    """Per-configuration ML-KEM policy attached to QuicConfiguration."""

    suite: str = "X25519"
    backend: Optional[str] = None
    tamper_ciphertext: bool = False
    tamper_ek: bool = False


@dataclass
class ConnectionMLKEMState:
    """Per-connection cryptographic telemetry and transient ML-KEM state."""

    role: str
    configured_suite: str
    backend_pref: Optional[str] = None
    tamper_ciphertext: bool = False
    tamper_ek: bool = False

    negotiated_suite: Optional[str] = None
    negotiated_group: Optional[int] = None
    is_hybrid: bool = False
    backend_used: str = "none"

    ek: Optional[bytes] = field(default=None, repr=False)
    dk: Optional[bytes] = field(default=None, repr=False)
    ct: Optional[bytes] = field(default=None, repr=False)
    ss_mlkem: Optional[bytes] = field(default=None, repr=False)
    ss_x25519: Optional[bytes] = field(default=None, repr=False)
    ss_effective: Optional[bytes] = field(default=None, repr=False)

    keygen_ms: float = 0.0
    encaps_ms: float = 0.0
    decaps_ms: float = 0.0

    client_share_bytes: int = 0
    server_share_bytes: int = 0
    client_hello_bytes: int = 0
    server_hello_bytes: int = 0

    key_schedule_bound: bool = False
    secret_sha256_prefix: str = ""
    mlkem_ss_sha256_prefix: str = ""

    def to_summary(self) -> Dict[str, object]:
        """Return safe non-secret telemetry dictionary for logging/assertions."""
        return {
            "role": self.role,
            "configured_suite": self.configured_suite,
            "negotiated_suite": self.negotiated_suite or "",
            "negotiated_group": (
                f"0x{self.negotiated_group:04x}" if self.negotiated_group is not None else ""
            ),
            "is_hybrid": self.is_hybrid,
            "backend_used": self.backend_used,
            "keygen_ms": round(self.keygen_ms, 4),
            "encaps_ms": round(self.encaps_ms, 4),
            "decaps_ms": round(self.decaps_ms, 4),
            "client_share_bytes": self.client_share_bytes,
            "server_share_bytes": self.server_share_bytes,
            "client_hello_bytes": self.client_hello_bytes,
            "server_hello_bytes": self.server_hello_bytes,
            "key_schedule_bound": self.key_schedule_bound,
            "mlkem_ss_sha256_prefix": self.mlkem_ss_sha256_prefix,
            "secret_sha256_prefix": self.secret_sha256_prefix,
        }


_INSTALLED = False
_DEFAULT_POLICY = MLKEMPolicy(suite="X25519")

_active_quic_config: contextvars.ContextVar[Optional[aioquic.quic.configuration.QuicConfiguration]] = (
    contextvars.ContextVar("mlkem_active_quic_config", default=None)
)
_active_quic_conn: contextvars.ContextVar[Optional[aioquic.quic.connection.QuicConnection]] = (
    contextvars.ContextVar("mlkem_active_quic_conn", default=None)
)
_active_tls_ctx: contextvars.ContextVar[Optional[aioquic.tls.Context]] = contextvars.ContextVar(
    "mlkem_active_tls_ctx", default=None
)

_ctx_states: "weakref.WeakKeyDictionary[aioquic.tls.Context, ConnectionMLKEMState]" = (
    weakref.WeakKeyDictionary()
)
_conn_states: "weakref.WeakKeyDictionary[aioquic.quic.connection.QuicConnection, ConnectionMLKEMState]" = (
    weakref.WeakKeyDictionary()
)
_ks_to_ctx: "weakref.WeakKeyDictionary[aioquic.tls.KeySchedule, aioquic.tls.Context]" = (
    weakref.WeakKeyDictionary()
)


def set_default_policy(
    suite: str = "X25519",
    *,
    backend: Optional[str] = None,
    tamper_ciphertext: bool = False,
    tamper_ek: bool = False,
) -> None:
    """Set fallback ML-KEM policy used when QuicConfiguration has no explicit policy."""
    global _DEFAULT_POLICY
    normalized = "AUTO" if suite.strip().upper() == "AUTO" else normalize_suite_name(suite)
    _DEFAULT_POLICY = MLKEMPolicy(
        suite=normalized,
        backend=backend,
        tamper_ciphertext=tamper_ciphertext,
        tamper_ek=tamper_ek,
    )


def configure_mlkem_suite(
    configuration: aioquic.quic.configuration.QuicConfiguration,
    suite: str = "X25519",
    *,
    backend: Optional[str] = None,
    tamper_ciphertext: bool = False,
    tamper_ek: bool = False,
) -> None:
    """Attach an ML-KEM suite policy directly to a QuicConfiguration instance."""
    normalized = "AUTO" if suite.strip().upper() == "AUTO" else normalize_suite_name(suite)
    setattr(
        configuration,
        "_mlkem_policy",
        MLKEMPolicy(
            suite=normalized,
            backend=backend,
            tamper_ciphertext=tamper_ciphertext,
            tamper_ek=tamper_ek,
        ),
    )


def get_connection_state(quic_conn: object) -> Optional[ConnectionMLKEMState]:
    """Retrieve ConnectionMLKEMState for a QuicConnection instance (if available)."""
    return _conn_states.get(quic_conn)  # type: ignore[arg-type]


def get_context_state(tls_ctx: aioquic.tls.Context) -> Optional[ConnectionMLKEMState]:
    """Retrieve ConnectionMLKEMState for an aioquic.tls.Context instance."""
    return _ctx_states.get(tls_ctx)


def get_latest_config_state(
    configuration: aioquic.quic.configuration.QuicConfiguration,
) -> Optional[ConnectionMLKEMState]:
    """Return the most recently created ConnectionMLKEMState for a QuicConfiguration."""
    return getattr(configuration, "_mlkem_latest_state", None)


# ---------------------------------------------------------------------------
# RFC 8446 ClientHello / ServerHello binary codec helpers
# ---------------------------------------------------------------------------


def _parse_extensions(ext_blob: bytes) -> List[Tuple[int, bytes]]:
    pos = 0
    end = len(ext_blob)
    exts: List[Tuple[int, bytes]] = []
    while pos < end:
        if pos + 4 > end:
            raise ValueError("Truncated TLS extension header")
        ext_type, ext_len = struct.unpack("!HH", ext_blob[pos : pos + 4])
        pos += 4
        if pos + ext_len > end:
            raise ValueError(f"Truncated TLS extension 0x{ext_type:04x}")
        exts.append((ext_type, ext_blob[pos : pos + ext_len]))
        pos += ext_len
    return exts


def _encode_extensions(exts: List[Tuple[int, bytes]]) -> bytes:
    out = bytearray()
    for ext_type, ext_data in exts:
        out.extend(struct.pack("!HH", ext_type, len(ext_data)))
        out.extend(ext_data)
    return struct.pack("!H", len(out)) + bytes(out)


def _decode_supported_groups(ext_data: bytes) -> List[int]:
    if len(ext_data) < 2:
        raise ValueError("Malformed supported_groups extension")
    (list_bytes,) = struct.unpack("!H", ext_data[:2])
    if 2 + list_bytes != len(ext_data) or list_bytes % 2 != 0:
        raise ValueError("Invalid supported_groups list length")
    return [
        struct.unpack("!H", ext_data[i : i + 2])[0]
        for i in range(2, 2 + list_bytes, 2)
    ]


def _encode_supported_groups(groups: List[int]) -> bytes:
    payload = b"".join(struct.pack("!H", g) for g in groups)
    return struct.pack("!H", len(payload)) + payload


def _decode_client_key_share(ext_data: bytes) -> List[Tuple[int, bytes]]:
    if len(ext_data) < 2:
        raise ValueError("Malformed client key_share extension")
    (shares_len,) = struct.unpack("!H", ext_data[:2])
    if 2 + shares_len != len(ext_data):
        raise ValueError("Invalid client key_share total length")
    pos = 2
    entries: List[Tuple[int, bytes]] = []
    while pos < len(ext_data):
        if pos + 4 > len(ext_data):
            raise ValueError("Truncated client KeyShareEntry")
        group, kex_len = struct.unpack("!HH", ext_data[pos : pos + 4])
        pos += 4
        if pos + kex_len > len(ext_data):
            raise ValueError("Truncated client key_exchange payload")
        entries.append((group, ext_data[pos : pos + kex_len]))
        pos += kex_len
    return entries


def _encode_client_key_share(entries: List[Tuple[int, bytes]]) -> bytes:
    inner = bytearray()
    for group, share in entries:
        inner.extend(struct.pack("!HH", group, len(share)))
        inner.extend(share)
    return struct.pack("!H", len(inner)) + bytes(inner)


def _decode_server_key_share(ext_data: bytes, is_hrr: bool) -> Tuple[int, bytes]:
    if is_hrr:
        if len(ext_data) != 2:
            raise ValueError("Invalid HelloRetryRequest key_share length")
        (group,) = struct.unpack("!H", ext_data)
        return group, b""
    if len(ext_data) < 4:
        raise ValueError("Malformed server key_share extension")
    group, kex_len = struct.unpack("!HH", ext_data[:4])
    if 4 + kex_len != len(ext_data):
        raise ValueError("Invalid server key_share length")
    return group, ext_data[4:]


def _encode_server_key_share(group: int, share: bytes, is_hrr: bool = False) -> bytes:
    if is_hrr:
        return struct.pack("!H", group)
    return struct.pack("!HH", group, len(share)) + share


def _pull_handshake_frame(buf: aioquic.buffer.Buffer) -> Tuple[int, bytes]:
    """Pull 4-byte TLS Handshake header (type + uint24 length) and exact body bytes."""
    hdr = buf.pull_bytes(4)
    msg_type = hdr[0]
    body_len = int.from_bytes(hdr[1:4], byteorder="big")
    raw_body = buf.pull_bytes(body_len)
    return msg_type, raw_body


def _wrap_handshake_frame(msg_type: int, body: bytes) -> bytes:
    """Re-attach 4-byte TLS Handshake framing header around a serialized body."""
    return bytes([msg_type]) + len(body).to_bytes(3, byteorder="big") + body


def _parse_client_hello_body(
    raw_body: bytes,
) -> Tuple[bytes, List[Tuple[int, bytes]], List[int], List[Tuple[int, bytes]]]:
    pos = 2 + 32  # legacy_version (2) + random (32)
    sid_len = raw_body[pos]
    pos += 1 + sid_len
    (cs_len,) = struct.unpack("!H", raw_body[pos : pos + 2])
    pos += 2 + cs_len
    cm_len = raw_body[pos]
    pos += 1 + cm_len
    (ext_total_len,) = struct.unpack("!H", raw_body[pos : pos + 2])
    prefix = raw_body[:pos]
    ext_blob = raw_body[pos + 2 : pos + 2 + ext_total_len]
    if pos + 2 + ext_total_len != len(raw_body):
        raise ValueError("ClientHello extensions do not align with message boundary")

    exts = _parse_extensions(ext_blob)
    groups: List[int] = []
    shares: List[Tuple[int, bytes]] = []
    for ext_type, ext_data in exts:
        if ext_type == EXT_SUPPORTED_GROUPS:
            groups = _decode_supported_groups(ext_data)
        elif ext_type == EXT_KEY_SHARE:
            shares = _decode_client_key_share(ext_data)
    return prefix, exts, groups, shares


def _rebuild_client_hello_body(
    prefix: bytes,
    exts: List[Tuple[int, bytes]],
    new_groups: List[int],
    new_shares: List[Tuple[int, bytes]],
) -> bytes:
    updated: List[Tuple[int, bytes]] = []
    saw_groups = False
    saw_shares = False
    for ext_type, ext_data in exts:
        if ext_type == EXT_SUPPORTED_GROUPS:
            updated.append((ext_type, _encode_supported_groups(new_groups)))
            saw_groups = True
        elif ext_type == EXT_KEY_SHARE:
            updated.append((ext_type, _encode_client_key_share(new_shares)))
            saw_shares = True
        else:
            updated.append((ext_type, ext_data))
    if not saw_groups:
        updated.append((EXT_SUPPORTED_GROUPS, _encode_supported_groups(new_groups)))
    if not saw_shares:
        updated.append((EXT_KEY_SHARE, _encode_client_key_share(new_shares)))
    return prefix + _encode_extensions(updated)


def _parse_server_hello_body(
    raw_body: bytes,
) -> Tuple[bytes, bool, List[Tuple[int, bytes]], Optional[int], bytes]:
    random_bytes = raw_body[2:34]
    is_hrr = random_bytes == _HRR_RANDOM
    pos = 34
    sid_len = raw_body[pos]
    pos += 1 + sid_len
    pos += 2 + 1  # cipher_suite (2) + legacy_compression_method (1)
    (ext_total_len,) = struct.unpack("!H", raw_body[pos : pos + 2])
    prefix = raw_body[:pos]
    ext_blob = raw_body[pos + 2 : pos + 2 + ext_total_len]
    if pos + 2 + ext_total_len != len(raw_body):
        raise ValueError("ServerHello extensions do not align with message boundary")

    exts = _parse_extensions(ext_blob)
    group: Optional[int] = None
    share = b""
    for ext_type, ext_data in exts:
        if ext_type == EXT_KEY_SHARE:
            group, share = _decode_server_key_share(ext_data, is_hrr=is_hrr)
    return prefix, is_hrr, exts, group, share


def _rebuild_server_hello_body(
    prefix: bytes,
    exts: List[Tuple[int, bytes]],
    new_group: int,
    new_share: bytes,
    is_hrr: bool = False,
) -> bytes:
    updated: List[Tuple[int, bytes]] = []
    saw_share = False
    for ext_type, ext_data in exts:
        if ext_type == EXT_KEY_SHARE:
            updated.append(
                (ext_type, _encode_server_key_share(new_group, new_share, is_hrr=is_hrr))
            )
            saw_share = True
        else:
            updated.append((ext_type, ext_data))
    if not saw_share:
        updated.append(
            (EXT_KEY_SHARE, _encode_server_key_share(new_group, new_share, is_hrr=is_hrr))
        )
    return prefix + _encode_extensions(updated)


# ---------------------------------------------------------------------------
# aioquic monkey-patch installer
# ---------------------------------------------------------------------------


def _alert_handshake_failure(message: str) -> BaseException:
    alert_cls = getattr(aioquic.tls, "AlertHandshakeFailure", None)
    if alert_cls is not None:
        return alert_cls(message)
    return ValueError(message)


def install_mlkem_tls() -> None:
    """Install per-context ML-KEM hooks into aioquic (idempotent)."""
    global _INSTALLED
    if _INSTALLED:
        return

    required_tls_attrs = (
        "Context",
        "KeySchedule",
        "push_client_hello",
        "pull_client_hello",
        "push_server_hello",
        "pull_server_hello",
    )
    missing = [name for name in required_tls_attrs if not hasattr(aioquic.tls, name)]
    if missing:
        raise RuntimeError(f"Unsupported aioquic.tls version; missing attributes: {missing}")

    orig_quic_conn_init = aioquic.quic.connection.QuicConnection.__init__
    orig_quic_conn_initialize = aioquic.quic.connection.QuicConnection._initialize
    orig_ctx_init = aioquic.tls.Context.__init__
    orig_ctx_handle_message = aioquic.tls.Context.handle_message
    orig_ks_init = aioquic.tls.KeySchedule.__init__
    orig_ks_extract = aioquic.tls.KeySchedule.extract
    orig_push_ch = aioquic.tls.push_client_hello
    orig_pull_ch = aioquic.tls.pull_client_hello
    orig_push_sh = aioquic.tls.push_server_hello
    orig_pull_sh = aioquic.tls.pull_server_hello

    @functools.wraps(orig_quic_conn_init)
    def wrapped_quic_conn_init(self, *args, **kwargs):
        config = kwargs.get("configuration")
        if config is None and args:
            for arg in args:
                if isinstance(arg, aioquic.quic.configuration.QuicConfiguration):
                    config = arg
                    break
        tok_cfg = _active_quic_config.set(config)
        tok_conn = _active_quic_conn.set(self)
        try:
            return orig_quic_conn_init(self, *args, **kwargs)
        finally:
            _active_quic_conn.reset(tok_conn)
            _active_quic_config.reset(tok_cfg)

    @functools.wraps(orig_quic_conn_initialize)
    def wrapped_quic_conn_initialize(self, peer_cid, *args, **kwargs):
        config = getattr(self, "_configuration", None) or getattr(self, "configuration", None)
        tok_cfg = _active_quic_config.set(config)
        tok_conn = _active_quic_conn.set(self)
        try:
            return orig_quic_conn_initialize(self, peer_cid, *args, **kwargs)
        finally:
            _active_quic_conn.reset(tok_conn)
            _active_quic_config.reset(tok_cfg)

    @functools.wraps(orig_ctx_init)
    def wrapped_ctx_init(self, *args, **kwargs):
        orig_ctx_init(self, *args, **kwargs)
        config = _active_quic_config.get()
        conn = _active_quic_conn.get()
        policy = getattr(config, "_mlkem_policy", _DEFAULT_POLICY) if config is not None else _DEFAULT_POLICY
        group_cls = getattr(aioquic.tls, "Group", None)
        if group_cls is not None and hasattr(group_cls, "X25519"):
            self._supported_groups = [group_cls.X25519]
        is_client = bool(kwargs.get("is_client", getattr(self, "is_client", args[0] if args else False)))
        state = ConnectionMLKEMState(
            role="client" if is_client else "server",
            configured_suite=policy.suite,
            backend_pref=policy.backend,
            tamper_ciphertext=policy.tamper_ciphertext,
            tamper_ek=policy.tamper_ek,
        )
        _ctx_states[self] = state
        if conn is not None:
            _conn_states[conn] = state
        if config is not None:
            setattr(config, "_mlkem_latest_state", state)

    @functools.wraps(orig_ctx_handle_message)
    def wrapped_ctx_handle_message(self, input_data, output_buf):
        tok = _active_tls_ctx.set(self)
        try:
            return orig_ctx_handle_message(self, input_data, output_buf)
        finally:
            _active_tls_ctx.reset(tok)

    @functools.wraps(orig_ks_init)
    def wrapped_ks_init(self, *args, **kwargs):
        orig_ks_init(self, *args, **kwargs)
        ctx = _active_tls_ctx.get()
        if ctx is not None:
            _ks_to_ctx[self] = ctx

    @functools.wraps(orig_ks_extract)
    def wrapped_ks_extract(self, key_material=None):
        ctx = _ks_to_ctx.get(self) or _active_tls_ctx.get()
        state = _ctx_states.get(ctx) if ctx is not None else None

        # In RFC 8446 / aioquic KeySchedule:
        #   generation == 0 -> Early Secret (PSK / zeros)
        #   generation == 1 -> Handshake Secret (DHE / KEM shared secret)
        #   generation == 2 -> Master Secret (zeros)
        if state is not None and self.generation == 1:
            suite_name = state.negotiated_suite or state.configured_suite
            if suite_name != "AUTO":
                spec = get_suite_spec(suite_name)
                if spec.is_pqc:
                    if state.ss_mlkem is None:
                        raise _alert_handshake_failure(
                            f"ML-KEM shared secret absent during {spec.name} KeySchedule.extract"
                        )
                    if spec.is_hybrid:
                        if key_material is None:
                            raise _alert_handshake_failure(
                                "X25519 shared secret missing for X25519-ML-KEM-768 hybrid extraction"
                            )
                        state.ss_x25519 = bytes(key_material)
                        # RFC 10024 Section 3.3: ML-KEM shared secret || X25519 shared secret
                        key_material = state.ss_mlkem + bytes(key_material)
                    else:
                        key_material = state.ss_mlkem
                    state.ss_effective = bytes(key_material)
                    state.secret_sha256_prefix = secret_fingerprint(state.ss_effective)
                    state.mlkem_ss_sha256_prefix = secret_fingerprint(state.ss_mlkem)
                    state.key_schedule_bound = True
                else:
                    if key_material is not None:
                        state.ss_x25519 = bytes(key_material)
                        state.ss_effective = bytes(key_material)
                        state.secret_sha256_prefix = secret_fingerprint(state.ss_effective)
                    state.key_schedule_bound = True

        return orig_ks_extract(self, key_material)

    @functools.wraps(orig_push_ch)
    def wrapped_push_client_hello(buf, hello):
        ctx = _active_tls_ctx.get()
        state = _ctx_states.get(ctx) if ctx is not None else None
        start_pos = buf.tell()
        orig_push_ch(buf, hello)
        end_pos = buf.tell()

        if state is None:
            return

        if state.configured_suite in ("X25519", "AUTO"):
            state.negotiated_suite = "X25519"
            state.negotiated_group = IANA_GROUP_X25519
            state.backend_used = "x25519"
            state.client_share_bytes = 32
            state.client_hello_bytes = end_pos - start_pos
            return

        spec = get_suite_spec(state.configured_suite)
        raw_frame = bytes(buf.data_slice(start_pos, end_pos))
        msg_type, raw_body = raw_frame[0], raw_frame[4:]
        prefix, exts, _groups, shares = _parse_client_hello_body(raw_body)

        x25519_client_pk: Optional[bytes] = None
        for grp, data in shares:
            if grp == IANA_GROUP_X25519:
                x25519_client_pk = data
                break
        if x25519_client_pk is None:
            raise _alert_handshake_failure(
                "aioquic ClientHello missing baseline X25519 key_share"
            )

        ek, dk, keygen_ms, backend_used = kem_keygen(spec.name, backend=state.backend_pref)
        wire_share = (ek + x25519_client_pk) if spec.is_hybrid else ek
        if state.tamper_ek:
            wire_share = flip_first_bit(wire_share)

        new_body = _rebuild_client_hello_body(
            prefix,
            exts,
            new_groups=[spec.iana_group],
            new_shares=[(spec.iana_group, wire_share)],
        )
        new_frame = _wrap_handshake_frame(msg_type, new_body)

        needed = start_pos + len(new_frame)
        if needed > buf.capacity:
            raise RuntimeError(
                f"TLS output buffer capacity ({buf.capacity}) too small for {spec.name} ClientHello ({needed})"
            )
        buf.seek(start_pos)
        buf.push_bytes(new_frame)

        state.negotiated_suite = spec.name
        state.negotiated_group = spec.iana_group
        state.is_hybrid = spec.is_hybrid
        state.backend_used = backend_used
        state.ek = ek
        state.dk = dk
        state.keygen_ms = keygen_ms
        state.client_share_bytes = len(wire_share)
        state.client_hello_bytes = len(new_frame)

    @functools.wraps(orig_pull_ch)
    def wrapped_pull_client_hello(buf):
        ctx = _active_tls_ctx.get()
        state = _ctx_states.get(ctx) if ctx is not None else None
        msg_type, raw_body = _pull_handshake_frame(buf)

        if state is None:
            return orig_pull_ch(
                aioquic.buffer.Buffer(data=_wrap_handshake_frame(msg_type, raw_body))
            )

        prefix, exts, _groups, shares = _parse_client_hello_body(raw_body)
        chosen_spec = None
        chosen_share = b""

        if state.configured_suite == "AUTO":
            for grp, share in shares:
                if grp in GROUP_TO_SUITE:
                    chosen_spec = GROUP_TO_SUITE[grp]
                    chosen_share = share
                    break
        else:
            expected_spec = get_suite_spec(state.configured_suite)
            for grp, share in shares:
                if grp == expected_spec.iana_group:
                    chosen_spec = expected_spec
                    chosen_share = share
                    break
            if chosen_spec is None:
                offered = [f"0x{g:04x}" for g, _ in shares]
                raise _alert_handshake_failure(
                    f"Server requires {expected_spec.name} (0x{expected_spec.iana_group:04x}), "
                    f"client offered {offered}"
                )

        if chosen_spec is None or not chosen_spec.is_pqc:
            state.negotiated_suite = "X25519"
            state.negotiated_group = IANA_GROUP_X25519
            state.backend_used = "x25519"
            state.client_share_bytes = len(chosen_share) if chosen_share else 32
            state.client_hello_bytes = 4 + len(raw_body)
            return orig_pull_ch(
                aioquic.buffer.Buffer(data=_wrap_handshake_frame(msg_type, raw_body))
            )

        if chosen_spec.is_hybrid:
            ek, client_x25519_pk = split_hybrid_client_share(chosen_share)
        else:
            if len(chosen_share) != chosen_spec.ek_bytes:
                raise _alert_handshake_failure(
                    f"Invalid {chosen_spec.name} ClientHello share length: {len(chosen_share)}"
                )
            ek = chosen_share
            client_x25519_pk = _DUMMY_X25519_PUB

        ct, ss_mlkem, encaps_ms, backend_used = kem_encaps(
            chosen_spec.name, ek, backend=state.backend_pref
        )

        state.negotiated_suite = chosen_spec.name
        state.negotiated_group = chosen_spec.iana_group
        state.is_hybrid = chosen_spec.is_hybrid
        state.backend_used = backend_used
        state.ek = ek
        state.ct = ct
        state.ss_mlkem = ss_mlkem
        state.encaps_ms = encaps_ms
        state.client_share_bytes = len(chosen_share)
        state.client_hello_bytes = 4 + len(raw_body)

        patched_body = _rebuild_client_hello_body(
            prefix,
            exts,
            new_groups=[IANA_GROUP_X25519],
            new_shares=[(IANA_GROUP_X25519, client_x25519_pk)],
        )
        return orig_pull_ch(
            aioquic.buffer.Buffer(data=_wrap_handshake_frame(msg_type, patched_body))
        )

    @functools.wraps(orig_push_sh)
    def wrapped_push_server_hello(buf, hello):
        ctx = _active_tls_ctx.get()
        state = _ctx_states.get(ctx) if ctx is not None else None
        start_pos = buf.tell()
        orig_push_sh(buf, hello)
        end_pos = buf.tell()

        if state is None:
            return

        raw_frame = bytes(buf.data_slice(start_pos, end_pos))
        if not state.negotiated_suite or not get_suite_spec(state.negotiated_suite).is_pqc:
            state.server_share_bytes = 32
            state.server_hello_bytes = len(raw_frame)
            return

        msg_type, raw_body = raw_frame[0], raw_frame[4:]
        spec = get_suite_spec(state.negotiated_suite)
        prefix, is_hrr, exts, _group, server_x25519_pk = _parse_server_hello_body(raw_body)
        if is_hrr:
            new_body = _rebuild_server_hello_body(
                prefix, exts, spec.iana_group, b"", is_hrr=True
            )
            state.server_share_bytes = 0
        else:
            if state.ct is None:
                raise _alert_handshake_failure(
                    f"Missing encapsulated ML-KEM ciphertext on ServerHello for {spec.name}"
                )
            ct_wire = flip_first_bit(state.ct) if state.tamper_ciphertext else state.ct
            wire_share = (ct_wire + server_x25519_pk) if spec.is_hybrid else ct_wire
            new_body = _rebuild_server_hello_body(
                prefix, exts, spec.iana_group, wire_share, is_hrr=False
            )
            state.server_share_bytes = len(wire_share)

        new_frame = _wrap_handshake_frame(msg_type, new_body)
        needed = start_pos + len(new_frame)
        if needed > buf.capacity:
            raise RuntimeError(
                f"TLS output buffer capacity ({buf.capacity}) too small for {spec.name} ServerHello ({needed})"
            )
        buf.seek(start_pos)
        buf.push_bytes(new_frame)
        state.server_hello_bytes = len(new_frame)

    @functools.wraps(orig_pull_sh)
    def wrapped_pull_server_hello(buf):
        ctx = _active_tls_ctx.get()
        state = _ctx_states.get(ctx) if ctx is not None else None
        msg_type, raw_body = _pull_handshake_frame(buf)

        if state is None:
            return orig_pull_sh(
                aioquic.buffer.Buffer(data=_wrap_handshake_frame(msg_type, raw_body))
            )

        prefix, is_hrr, exts, server_group, server_wire_share = _parse_server_hello_body(
            raw_body
        )
        if server_group is None:
            return orig_pull_sh(
                aioquic.buffer.Buffer(data=_wrap_handshake_frame(msg_type, raw_body))
            )

        if is_hrr:
            if state.negotiated_group is not None and server_group == state.negotiated_group:
                patched_body = _rebuild_server_hello_body(
                    prefix, exts, IANA_GROUP_X25519, b"", is_hrr=True
                )
                return orig_pull_sh(
                    aioquic.buffer.Buffer(data=_wrap_handshake_frame(msg_type, patched_body))
                )
            return orig_pull_sh(
                aioquic.buffer.Buffer(data=_wrap_handshake_frame(msg_type, raw_body))
            )

        if server_group in GROUP_TO_SUITE and GROUP_TO_SUITE[server_group].is_pqc:
            spec = GROUP_TO_SUITE[server_group]
            if state.negotiated_suite and state.negotiated_suite != spec.name:
                raise _alert_handshake_failure(
                    f"Server returned group 0x{server_group:04x} ({spec.name}), "
                    f"expected {state.negotiated_suite}"
                )
            if state.dk is None:
                raise _alert_handshake_failure(
                    "Client ML-KEM decapsulation key missing when handling ServerHello"
                )
            if spec.is_hybrid:
                ct, server_x25519_pk = split_hybrid_server_share(server_wire_share)
            else:
                if len(server_wire_share) != spec.ct_bytes:
                    raise _alert_handshake_failure(
                        f"Invalid {spec.name} ServerHello share length: {len(server_wire_share)}"
                    )
                ct = server_wire_share
                server_x25519_pk = _DUMMY_X25519_PUB

            ss_mlkem, decaps_ms, backend_used = kem_decaps(
                spec.name, state.dk, ct, backend=state.backend_pref
            )
            state.ct = ct
            state.ss_mlkem = ss_mlkem
            state.decaps_ms = decaps_ms
            state.backend_used = backend_used
            state.server_share_bytes = len(server_wire_share)
            state.server_hello_bytes = 4 + len(raw_body)

            patched_body = _rebuild_server_hello_body(
                prefix, exts, IANA_GROUP_X25519, server_x25519_pk, is_hrr=False
            )
            return orig_pull_sh(
                aioquic.buffer.Buffer(data=_wrap_handshake_frame(msg_type, patched_body))
            )

        # Non-PQC server group received (e.g. X25519)
        if state.configured_suite not in ("X25519", "AUTO"):
            raise _alert_handshake_failure(
                f"Downgrade detected: expected {state.configured_suite}, received group 0x{server_group:04x}"
            )
        state.server_share_bytes = len(server_wire_share)
        state.server_hello_bytes = 4 + len(raw_body)
        return orig_pull_sh(
            aioquic.buffer.Buffer(data=_wrap_handshake_frame(msg_type, raw_body))
        )

    aioquic.quic.connection.QuicConnection.__init__ = wrapped_quic_conn_init
    aioquic.quic.connection.QuicConnection._initialize = wrapped_quic_conn_initialize
    aioquic.tls.Context.__init__ = wrapped_ctx_init
    aioquic.tls.Context.handle_message = wrapped_ctx_handle_message
    aioquic.tls.KeySchedule.__init__ = wrapped_ks_init
    aioquic.tls.KeySchedule.extract = wrapped_ks_extract
    aioquic.tls.push_client_hello = wrapped_push_client_hello
    aioquic.tls.pull_client_hello = wrapped_pull_client_hello
    aioquic.tls.push_server_hello = wrapped_push_server_hello
    aioquic.tls.pull_server_hello = wrapped_pull_server_hello
    _INSTALLED = True
