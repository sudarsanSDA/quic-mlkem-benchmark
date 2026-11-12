"""FIPS 203 ML-KEM and RFC 10024 X25519MLKEM768 cryptographic primitives.

Provides real post-quantum key generation, encapsulation, decapsulation,
length validation, hybrid X25519+ML-KEM combination, and nanosecond-resolution
timing for TLS 1.3 / QUIC integration.

Backend priority:
  1. ``liboqs`` (``oqs.KeyEncapsulation`` backed by C liboqs)
  2. ``cryptography`` (OpenSSL 3.5+ ``cryptography.hazmat.primitives.asymmetric.mlkem``)
  3. ``kyber_py`` (pure-Python FIPS 203 reference fallback for functional checks only)
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class SuiteSpec:
    """Wire and cryptographic parameter specification for a key exchange suite."""

    name: str
    iana_group: int
    kem_alg: Optional[str]
    is_pqc: bool
    is_hybrid: bool
    ek_bytes: int
    ct_bytes: int
    ss_bytes: int
    client_share_bytes: int
    server_share_bytes: int
    tls_shared_secret_bytes: int


IANA_GROUP_X25519 = 0x001D
IANA_GROUP_MLKEM512 = 0x0200
IANA_GROUP_MLKEM768 = 0x0201
IANA_GROUP_MLKEM1024 = 0x0202
IANA_GROUP_X25519_MLKEM768 = 0x11EC

SUITE_SPECS: Dict[str, SuiteSpec] = {
    "X25519": SuiteSpec(
        name="X25519",
        iana_group=IANA_GROUP_X25519,
        kem_alg=None,
        is_pqc=False,
        is_hybrid=False,
        ek_bytes=32,
        ct_bytes=32,
        ss_bytes=32,
        client_share_bytes=32,
        server_share_bytes=32,
        tls_shared_secret_bytes=32,
    ),
    "ML-KEM-512": SuiteSpec(
        name="ML-KEM-512",
        iana_group=IANA_GROUP_MLKEM512,
        kem_alg="ML-KEM-512",
        is_pqc=True,
        is_hybrid=False,
        ek_bytes=800,
        ct_bytes=768,
        ss_bytes=32,
        client_share_bytes=800,
        server_share_bytes=768,
        tls_shared_secret_bytes=32,
    ),
    "ML-KEM-768": SuiteSpec(
        name="ML-KEM-768",
        iana_group=IANA_GROUP_MLKEM768,
        kem_alg="ML-KEM-768",
        is_pqc=True,
        is_hybrid=False,
        ek_bytes=1184,
        ct_bytes=1088,
        ss_bytes=32,
        client_share_bytes=1184,
        server_share_bytes=1088,
        tls_shared_secret_bytes=32,
    ),
    "ML-KEM-1024": SuiteSpec(
        name="ML-KEM-1024",
        iana_group=IANA_GROUP_MLKEM1024,
        kem_alg="ML-KEM-1024",
        is_pqc=True,
        is_hybrid=False,
        ek_bytes=1568,
        ct_bytes=1568,
        ss_bytes=32,
        client_share_bytes=1568,
        server_share_bytes=1568,
        tls_shared_secret_bytes=32,
    ),
    "X25519-ML-KEM-768": SuiteSpec(
        name="X25519-ML-KEM-768",
        iana_group=IANA_GROUP_X25519_MLKEM768,
        kem_alg="ML-KEM-768",
        is_pqc=True,
        is_hybrid=True,
        ek_bytes=1184,
        ct_bytes=1088,
        ss_bytes=32,
        # RFC 10024 Section 3.2: client share = ML-KEM-768 ek (1184B) || X25519 pk (32B)
        client_share_bytes=1216,
        # RFC 10024 Section 3.2: server share = ML-KEM-768 ct (1088B) || X25519 pk (32B)
        server_share_bytes=1120,
        # RFC 10024 Section 3.3: shared secret = ML-KEM-768 ss (32B) || X25519 ss (32B)
        tls_shared_secret_bytes=64,
    ),
}

GROUP_TO_SUITE: Dict[int, SuiteSpec] = {
    spec.iana_group: spec for spec in SUITE_SPECS.values()
}

ALIAS_TO_SUITE: Dict[str, str] = {
    "x25519": "X25519",
    "ml-kem-512": "ML-KEM-512",
    "mlkem512": "ML-KEM-512",
    "ml-kem-768": "ML-KEM-768",
    "mlkem768": "ML-KEM-768",
    "ml-kem-1024": "ML-KEM-1024",
    "mlkem1024": "ML-KEM-1024",
    "x25519-ml-kem-768": "X25519-ML-KEM-768",
    "x25519mlkem768": "X25519-ML-KEM-768",
}


class MLKEMBackendError(RuntimeError):
    """Raised when no usable FIPS 203 ML-KEM cryptographic backend is available."""


def normalize_suite_name(name: str) -> str:
    """Normalize user-provided cipher suite string to canonical identifier."""
    key = name.strip().lower()
    if key in ALIAS_TO_SUITE:
        return ALIAS_TO_SUITE[key]
    if name in SUITE_SPECS:
        return name
    raise ValueError(
        f"Unsupported suite '{name}'. Expected one of: {list(SUITE_SPECS.keys())}"
    )


def get_suite_spec(name: str) -> SuiteSpec:
    """Return immutable parameter specification for the given suite name."""
    return SUITE_SPECS[normalize_suite_name(name)]


def _try_import_oqs():
    try:
        import oqs  # type: ignore

        return oqs
    except Exception:
        return None


def _try_import_cryptography_mlkem():
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem  # type: ignore

        return mlkem
    except Exception:
        return None


def _try_import_kyber_py():
    try:
        from kyber_py import ml_kem  # type: ignore

        return ml_kem
    except Exception:
        return None


def detect_backend(kem_alg: str, allow_pure_python: bool = True) -> str:
    """Detect the highest-priority FIPS 203 backend supporting ``kem_alg``."""
    oqs = _try_import_oqs()
    if oqs is not None:
        try:
            enabled = set(oqs.get_enabled_kem_mechanisms())
        except Exception:
            enabled = set()
        if not enabled or kem_alg in enabled:
            return "liboqs"

    mlkem_mod = _try_import_cryptography_mlkem()
    if mlkem_mod is not None:
        class_prefix = kem_alg.replace("-", "")
        if hasattr(mlkem_mod, f"{class_prefix}PrivateKey") and hasattr(
            mlkem_mod, f"{class_prefix}PublicKey"
        ):
            return "cryptography"

    if allow_pure_python:
        kyber_mod = _try_import_kyber_py()
        attr_name = kem_alg.replace("-", "_")
        if kyber_mod is not None and hasattr(kyber_mod, attr_name):
            return "kyber_py"

    raise MLKEMBackendError(
        f"No FIPS 203 backend found for {kem_alg}. "
        "Install liboqs + liboqs-python (recommended for C/AVX2 benchmarks), "
        "cryptography >= 48 (with OpenSSL 3.5+), or kyber-py (for unit tests)."
    )


def warmup_backend(suite: str, backend: Optional[str] = None) -> Optional[str]:
    """Preload and initialize the FIPS 203 backend before timed handshakes.

    Prevents one-time dynamic-linker / ctypes ``liboqs.so`` load latency (~25 ms)
    from leaking into per-connection handshake measurements.
    """
    spec = get_suite_spec(suite)
    if not spec.is_pqc or spec.kem_alg is None:
        return None
    chosen = backend or detect_backend(spec.kem_alg)
    if chosen == "liboqs":
        oqs = _try_import_oqs()
        if oqs is not None:
            with oqs.KeyEncapsulation(spec.kem_alg):
                pass
    elif chosen == "cryptography":
        _cryptography_key_classes(spec.kem_alg)
    elif chosen == "kyber_py":
        _try_import_kyber_py()
    return chosen


def _cryptography_key_classes(kem_alg: str):
    mlkem_mod = _try_import_cryptography_mlkem()
    if mlkem_mod is None:
        raise MLKEMBackendError("cryptography.hazmat.primitives.asymmetric.mlkem unavailable")
    prefix = kem_alg.replace("-", "")
    priv_cls = getattr(mlkem_mod, f"{prefix}PrivateKey", None)
    pub_cls = getattr(mlkem_mod, f"{prefix}PublicKey", None)
    if priv_cls is None or pub_cls is None:
        raise MLKEMBackendError(f"cryptography.mlkem does not support {kem_alg}")
    return priv_cls, pub_cls


def kem_keygen(suite: str, backend: Optional[str] = None) -> Tuple[bytes, bytes, float, str]:
    """Generate a real FIPS 203 ML-KEM keypair.

    Returns ``(encapsulation_key, decapsulation_key, elapsed_ms, backend_used)``.
    """
    spec = get_suite_spec(suite)
    if not spec.is_pqc or spec.kem_alg is None:
        raise ValueError(f"Suite {spec.name} is classical and does not use ML-KEM")

    chosen = backend or detect_backend(spec.kem_alg)
    t0 = time.perf_counter_ns()

    if chosen == "liboqs":
        oqs = _try_import_oqs()
        if oqs is None:
            raise MLKEMBackendError("liboqs-python is not installed")
        with oqs.KeyEncapsulation(spec.kem_alg) as kem:
            ek = kem.generate_keypair()
            dk = kem.export_secret_key()
    elif chosen == "cryptography":
        priv_cls, _ = _cryptography_key_classes(spec.kem_alg)
        priv = priv_cls.generate()
        ek = priv.public_key().public_bytes_raw()
        dk = priv.private_bytes_raw()
    elif chosen == "kyber_py":
        kyber_mod = _try_import_kyber_py()
        if kyber_mod is None:
            raise MLKEMBackendError("kyber-py is not installed")
        impl = getattr(kyber_mod, spec.kem_alg.replace("-", "_"))
        ek, dk = impl.keygen()
    else:
        raise ValueError(f"Unknown ML-KEM backend '{chosen}'")

    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    if len(ek) != spec.ek_bytes:
        raise ValueError(
            f"{spec.kem_alg} ek length mismatch: got {len(ek)}, expected {spec.ek_bytes}"
        )
    return bytes(ek), bytes(dk), elapsed_ms, chosen


def kem_encaps(
    suite: str, ek: bytes, backend: Optional[str] = None
) -> Tuple[bytes, bytes, float, str]:
    """Encapsulate a 32-byte shared secret against peer's encapsulation key.

    Returns ``(ciphertext, shared_secret, elapsed_ms, backend_used)``.
    """
    spec = get_suite_spec(suite)
    if not spec.is_pqc or spec.kem_alg is None:
        raise ValueError(f"Suite {spec.name} is classical and does not use ML-KEM")
    if len(ek) != spec.ek_bytes:
        raise ValueError(
            f"Invalid {spec.kem_alg} encapsulation key size: got {len(ek)}, expected {spec.ek_bytes}"
        )

    chosen = backend or detect_backend(spec.kem_alg)
    t0 = time.perf_counter_ns()

    if chosen == "liboqs":
        oqs = _try_import_oqs()
        if oqs is None:
            raise MLKEMBackendError("liboqs-python is not installed")
        with oqs.KeyEncapsulation(spec.kem_alg) as kem:
            ct, ss = kem.encap_secret(ek)
    elif chosen == "cryptography":
        _, pub_cls = _cryptography_key_classes(spec.kem_alg)
        pub = pub_cls.from_public_bytes(ek)
        # Note: cryptography returns (shared_key, ciphertext)
        ss, ct = pub.encapsulate()
    elif chosen == "kyber_py":
        kyber_mod = _try_import_kyber_py()
        if kyber_mod is None:
            raise MLKEMBackendError("kyber-py is not installed")
        impl = getattr(kyber_mod, spec.kem_alg.replace("-", "_"))
        # Note: kyber_py ML_KEM_* returns (shared_key, ciphertext) per FIPS 203
        ss, ct = impl.encaps(ek)
    else:
        raise ValueError(f"Unknown ML-KEM backend '{chosen}'")

    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    if len(ct) != spec.ct_bytes or len(ss) != spec.ss_bytes:
        raise ValueError(
            f"{spec.kem_alg} encaps output size mismatch: ct={len(ct)} (exp {spec.ct_bytes}), ss={len(ss)}"
        )
    return bytes(ct), bytes(ss), elapsed_ms, chosen


def kem_decaps(
    suite: str, dk: bytes, ct: bytes, backend: Optional[str] = None
) -> Tuple[bytes, float, str]:
    """Decapsulate a peer ciphertext using the local decapsulation key.

    Note that per FIPS 203 implicit rejection, malformed/tampered ciphertexts
    still output a pseudorandom 32-byte value unrelated to the sender's secret,
    which then fails TLS 1.3 Finished / AEAD verification.

    Returns ``(shared_secret, elapsed_ms, backend_used)``.
    """
    spec = get_suite_spec(suite)
    if not spec.is_pqc or spec.kem_alg is None:
        raise ValueError(f"Suite {spec.name} is classical and does not use ML-KEM")
    if len(ct) != spec.ct_bytes:
        raise ValueError(
            f"Invalid {spec.kem_alg} ciphertext size: got {len(ct)}, expected {spec.ct_bytes}"
        )

    chosen = backend or detect_backend(spec.kem_alg)
    t0 = time.perf_counter_ns()

    if chosen == "liboqs":
        oqs = _try_import_oqs()
        if oqs is None:
            raise MLKEMBackendError("liboqs-python is not installed")
        with oqs.KeyEncapsulation(spec.kem_alg, secret_key=dk) as kem:
            ss = kem.decap_secret(ct)
    elif chosen == "cryptography":
        priv_cls, _ = _cryptography_key_classes(spec.kem_alg)
        if hasattr(priv_cls, "from_seed_bytes"):
            priv = priv_cls.from_seed_bytes(dk)
        elif hasattr(priv_cls, "from_private_bytes"):
            priv = priv_cls.from_private_bytes(dk)
        else:
            raise MLKEMBackendError(
                f"{priv_cls.__name__} provides neither from_seed_bytes nor from_private_bytes"
            )
        ss = priv.decapsulate(ct)
    elif chosen == "kyber_py":
        kyber_mod = _try_import_kyber_py()
        if kyber_mod is None:
            raise MLKEMBackendError("kyber-py is not installed")
        impl = getattr(kyber_mod, spec.kem_alg.replace("-", "_"))
        ss = impl.decaps(dk, ct)
    else:
        raise ValueError(f"Unknown ML-KEM backend '{chosen}'")

    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    if len(ss) != spec.ss_bytes:
        raise ValueError(
            f"{spec.kem_alg} decaps shared secret size mismatch: got {len(ss)}, expected {spec.ss_bytes}"
        )
    return bytes(ss), elapsed_ms, chosen


def split_hybrid_client_share(wire_share: bytes) -> Tuple[bytes, bytes]:
    """Split RFC 10024 X25519MLKEM768 client share into (mlkem_ek, x25519_pk)."""
    spec = SUITE_SPECS["X25519-ML-KEM-768"]
    if len(wire_share) != spec.client_share_bytes:
        raise ValueError(
            f"Invalid X25519MLKEM768 client share size: got {len(wire_share)}, "
            f"expected {spec.client_share_bytes}"
        )
    return wire_share[: spec.ek_bytes], wire_share[spec.ek_bytes :]


def split_hybrid_server_share(wire_share: bytes) -> Tuple[bytes, bytes]:
    """Split RFC 10024 X25519MLKEM768 server share into (mlkem_ct, x25519_pk)."""
    spec = SUITE_SPECS["X25519-ML-KEM-768"]
    if len(wire_share) != spec.server_share_bytes:
        raise ValueError(
            f"Invalid X25519MLKEM768 server share size: got {len(wire_share)}, "
            f"expected {spec.server_share_bytes}"
        )
    return wire_share[: spec.ct_bytes], wire_share[spec.ct_bytes :]


def secret_fingerprint(secret: Optional[bytes]) -> str:
    """Return non-secret SHA-256 hex digest prefix for endpoint secret verification."""
    if not secret:
        return ""
    return hashlib.sha256(secret).hexdigest()[:16]


def flip_first_bit(data: bytes) -> bytes:
    """Flip the least-significant bit of the first byte for negative tamper tests."""
    if not data:
        raise ValueError("Cannot tamper empty byte string")
    return bytes([data[0] ^ 0x01]) + data[1:]
