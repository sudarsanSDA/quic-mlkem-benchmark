"""Pure-Python binary PCAP parser and QUIC RFC 9000 §8.1 flight analyzer.

Parses libpcap trace files directly via ``struct`` without invoking external
``tshark`` / ``pyshark`` processes, extracting per-direction IP/UDP byte and
packet counts as well as RFC 9000 Section 8.1 pre-address-validation flights.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import socket
import struct
from typing import Dict, List, Optional


@dataclass(frozen=True)
class QUICDatagram:
    """Single parsed UDP datagram carrying one or more coalesced QUIC packets."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ip_len: int
    udp_payload_len: int
    wire_len: int
    is_long_header: bool
    quic_long_type: Optional[int]  # 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
    has_validation_packet: bool = False


def _decode_quic_varint(buf: bytes, pos: int) -> Optional[tuple[int, int]]:
    """Decode an RFC 9000 variable-length integer starting at ``pos``."""
    if pos >= len(buf):
        return None
    prefix = buf[pos] >> 6
    length = 1 << prefix
    if pos + length > len(buf):
        return None
    val = buf[pos] & 0x3F
    for idx in range(1, length):
        val = (val << 8) | buf[pos + idx]
    return val, pos + length


def _classify_coalesced_quic_packets(payload: bytes) -> tuple[bool, Optional[int], bool]:
    """Walk coalesced QUIC packets inside one UDP datagram.

    Returns ``(first_is_long, first_long_type, has_validation_packet)`` where
    ``has_validation_packet`` is True if any coalesced QUIC packet in the
    datagram is a Handshake (long_type == 2) or 1-RTT Short Header packet.
    """
    if not payload:
        return False, None, False

    first_byte = payload[0]
    first_is_long = bool(first_byte & 0x80)
    first_long_type = ((first_byte & 0x30) >> 4) if first_is_long else None
    has_val = False

    off = 0
    end = len(payload)
    while off < end:
        b0 = payload[off]
        if b0 == 0x00:
            break
        if (b0 & 0x80) == 0:
            has_val = True
            break

        # Long Header: 1B flags + 4B version + 1B DCID len + DCID + 1B SCID len + SCID
        if off + 7 > end:
            break
        version = payload[off + 1 : off + 5]
        if version == b"\x00\x00\x00\x00":  # Version Negotiation
            break
        ltype = (b0 & 0x30) >> 4
        if ltype == 2:
            has_val = True
        if ltype == 3:  # Retry packet occupies remainder of datagram
            break

        dcid_len = payload[off + 5]
        scid_len_pos = off + 6 + dcid_len
        if scid_len_pos >= end:
            break
        scid_len = payload[scid_len_pos]
        pos = scid_len_pos + 1 + scid_len
        if pos > end:
            break

        if ltype == 0:  # Initial packet carries Token Length + Token
            tok_dec = _decode_quic_varint(payload, pos)
            if tok_dec is None:
                break
            tok_len, pos = tok_dec
            pos += tok_len
            if pos > end:
                break

        len_dec = _decode_quic_varint(payload, pos)
        if len_dec is None:
            break
        pkt_len, pos = len_dec
        off = pos + pkt_len

    return first_is_long, first_long_type, has_val


def _parse_pcap_packets(pcap_path: str) -> tuple[int, List[tuple[float, int, bytes]]]:
    """Read raw packets from a standard libpcap file."""
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) < 24:
        return -1, []

    with open(pcap_path, "rb") as f:
        ghdr = f.read(24)
        if len(ghdr) < 24:
            return -1, []

        magic = ghdr[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
            nano = magic == b"\x4d\x3c\xb2\xa1"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
            nano = magic == b"\xa1\xb2\x3c\x4d"
        else:
            return -1, []

        _ver_maj, _ver_min, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack(
            f"{endian}HHIIII", ghdr[4:]
        )

        records: List[tuple[float, int, bytes]] = []
        rec_fmt = f"{endian}IIII"
        while True:
            rhdr = f.read(16)
            if len(rhdr) < 16:
                break
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(rec_fmt, rhdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            ts = ts_sec + (ts_sub * (1e-9 if nano else 1e-6))
            records.append((ts, orig_len, pkt_data))

    return linktype, records


def _extract_ip_offset(linktype: int, pkt: bytes) -> Optional[int]:
    """Return byte offset where IPv4/IPv6 header starts for supported linktypes."""
    if linktype == 1:  # LINKTYPE_ETHERNET
        if len(pkt) < 14:
            return None
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        off = 14
        while ethertype in (0x8100, 0x88A8):
            if len(pkt) < off + 4:
                return None
            ethertype = struct.unpack("!H", pkt[off + 2 : off + 4])[0]
            off += 4
        if ethertype in (0x0800, 0x86DD):
            return off
        return None
    if linktype == 113:  # LINKTYPE_LINUX_SLL
        if len(pkt) < 16:
            return None
        proto = struct.unpack("!H", pkt[14:16])[0]
        return 16 if proto in (0x0800, 0x86DD) else None
    if linktype == 276:  # LINKTYPE_LINUX_SLL2
        if len(pkt) < 20:
            return None
        proto = struct.unpack("!H", pkt[0:2])[0]
        return 20 if proto in (0x0800, 0x86DD) else None
    if linktype == 101:  # LINKTYPE_RAW
        return 0
    if linktype == 0:  # LINKTYPE_NULL
        return 4 if len(pkt) >= 4 else None
    return None


def parse_quic_udp_trace(
    pcap_path: str, server_port: Optional[int] = 4433
) -> List[QUICDatagram]:
    """Parse all UDP QUIC datagrams in a PCAP file."""
    linktype, records = _parse_pcap_packets(pcap_path)
    if linktype < 0:
        return []

    datagrams: List[QUICDatagram] = []
    for ts, wire_len, raw in records:
        ip_off = _extract_ip_offset(linktype, raw)
        if ip_off is None or ip_off >= len(raw):
            continue

        version = (raw[ip_off] >> 4) & 0x0F
        if version == 4:
            if len(raw) < ip_off + 20:
                continue
            ihl = (raw[ip_off] & 0x0F) * 4
            ip_total_len = struct.unpack("!H", raw[ip_off + 2 : ip_off + 4])[0]
            proto = raw[ip_off + 9]
            if proto != 17 or len(raw) < ip_off + ihl + 8:
                continue
            src_ip = socket.inet_ntop(socket.AF_INET, raw[ip_off + 12 : ip_off + 16])
            dst_ip = socket.inet_ntop(socket.AF_INET, raw[ip_off + 16 : ip_off + 20])
            udp_off = ip_off + ihl
        elif version == 6:
            if len(raw) < ip_off + 48:
                continue
            payload_len = struct.unpack("!H", raw[ip_off + 4 : ip_off + 6])[0]
            ip_total_len = 40 + payload_len
            next_hdr = raw[ip_off + 6]
            if next_hdr != 17:
                continue
            src_ip = socket.inet_ntop(socket.AF_INET6, raw[ip_off + 8 : ip_off + 24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, raw[ip_off + 24 : ip_off + 40])
            udp_off = ip_off + 40
        else:
            continue

        sport, dport, udp_len, _cksum = struct.unpack("!HHHH", raw[udp_off : udp_off + 8])
        if udp_len < 9:
            continue
        if server_port is not None and sport != server_port and dport != server_port:
            continue

        quic_off = udp_off + 8
        udp_end = min(len(raw), udp_off + udp_len)
        if quic_off >= udp_end:
            continue
        is_long, long_type, has_val = _classify_coalesced_quic_packets(raw[quic_off:udp_end])

        datagrams.append(
            QUICDatagram(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                ip_len=ip_total_len,
                udp_payload_len=udp_len - 8,
                wire_len=wire_len,
                is_long_header=is_long,
                quic_long_type=long_type,
                has_validation_packet=has_val,
            )
        )

    return datagrams


def analyze_pcap(
    pcap_path: str,
    *,
    client_ip: Optional[str] = "10.0.0.1",
    server_ip: Optional[str] = "10.0.0.2",
    server_port: int = 4433,
) -> Dict[str, object]:
    """Compute traffic totals and RFC 9000 §8.1 pre-validation metrics from a PCAP."""
    datagrams = parse_quic_udp_trace(pcap_path, server_port=server_port)
    if not datagrams:
        return {
            "total_ip_bytes_client": 0,
            "total_ip_bytes_server": 0,
            "total_udp_bytes_client": 0,
            "total_udp_bytes_server": 0,
            "packets_client": 0,
            "packets_server": 0,
            "client_flight1_udp_bytes": 0,
            "client_preval_udp_bytes": 0,
            "server_preval_udp_bytes": 0,
            "amp_limit_3x_udp_bytes": 0,
            "amp_ratio": 0.0,
            "amp_budget_utilization": 0.0,
        }

    def is_from_client(d: QUICDatagram) -> bool:
        if client_ip and server_ip:
            if d.src_ip == client_ip:
                return True
            if d.src_ip == server_ip:
                return False
        return d.dst_port == server_port

    total_ip_c = total_ip_s = 0
    total_udp_c = total_udp_s = 0
    pkts_c = pkts_s = 0

    first_server_idx: Optional[int] = None
    first_client_val_idx: Optional[int] = None

    for idx, d in enumerate(datagrams):
        if is_from_client(d):
            total_ip_c += d.ip_len
            total_udp_c += d.udp_payload_len
            pkts_c += 1
            # RFC 9000 Section 8.1: Server validates client address upon receiving
            # a Handshake packet (long_type == 2) or 1-RTT Short Header packet,
            # including when coalesced behind an Initial ACK in the same datagram.
            if first_client_val_idx is None and d.has_validation_packet:
                first_client_val_idx = idx
        else:
            total_ip_s += d.ip_len
            total_udp_s += d.udp_payload_len
            pkts_s += 1
            if first_server_idx is None:
                first_server_idx = idx

    client_flight1_udp = 0
    client_preval_udp = 0
    server_preval_udp = 0

    for idx, d in enumerate(datagrams):
        if is_from_client(d):
            if first_server_idx is None or idx < first_server_idx:
                client_flight1_udp += d.udp_payload_len
            if first_client_val_idx is None or idx < first_client_val_idx:
                client_preval_udp += d.udp_payload_len
        else:
            if first_client_val_idx is None or idx < first_client_val_idx:
                server_preval_udp += d.udp_payload_len

    amp_limit_3x = 3 * client_preval_udp
    amp_ratio = (server_preval_udp / client_preval_udp) if client_preval_udp > 0 else 0.0
    amp_util = (server_preval_udp / amp_limit_3x) if amp_limit_3x > 0 else 0.0

    return {
        "total_ip_bytes_client": total_ip_c,
        "total_ip_bytes_server": total_ip_s,
        "total_udp_bytes_client": total_udp_c,
        "total_udp_bytes_server": total_udp_s,
        "packets_client": pkts_c,
        "packets_server": pkts_s,
        "client_flight1_udp_bytes": client_flight1_udp,
        "client_preval_udp_bytes": client_preval_udp,
        "server_preval_udp_bytes": server_preval_udp,
        "amp_limit_3x_udp_bytes": amp_limit_3x,
        "amp_ratio": round(amp_ratio, 4),
        "amp_budget_utilization": round(amp_util, 4),
    }

