"""
SRCES - Secure Remote Command Execution System
Common Protocol Definitions and Cryptographic Utilities
"""

import json
import struct
import hashlib
import hmac
import os
import time
from enum import IntEnum
from dataclasses import dataclass, asdict
from typing import Optional


# ─────────────────────────────────────────────
# Protocol Constants
# ─────────────────────────────────────────────
PROTOCOL_VERSION = 1
MAGIC_BYTES = bytes([0x53, 0x52, 0x43, 0x45])  # SRCE
HEADER_SIZE = 16   # magic(4) + version(1) + msg_type(1) + flags(2) + length(4) + checksum(4)
MAX_PAYLOAD = 65536
SESSION_TIMEOUT = 3600          # 1 hour
NONCE_SIZE = 16
KEY_SIZE = 32
HMAC_SIZE = 32


# ─────────────────────────────────────────────
# Message Types
# ─────────────────────────────────────────────
class MsgType(IntEnum):
    AUTH_CHALLENGE  = 0x01
    AUTH_RESPONSE   = 0x02
    AUTH_RESULT     = 0x03
    CMD_REQUEST     = 0x10
    CMD_RESPONSE    = 0x11
    CMD_STREAM      = 0x12
    KEEPALIVE       = 0x20
    DISCONNECT      = 0x21
    ERROR           = 0xFF


class AuthStatus(IntEnum):
    SUCCESS         = 0
    INVALID_CREDS   = 1
    ACCOUNT_LOCKED  = 2
    EXPIRED         = 3
    RATE_LIMITED    = 4


class CmdStatus(IntEnum):
    SUCCESS         = 0
    NOT_FOUND       = 1
    PERMISSION_DENIED = 2
    TIMEOUT         = 3
    ERROR           = 4


# ─────────────────────────────────────────────
# Packet Header
# ─────────────────────────────────────────────
# Wire format:
#  [4]  MAGIC
#  [1]  VERSION
#  [1]  MSG_TYPE
#  [2]  FLAGS
#  [4]  PAYLOAD_LENGTH
#  [4]  CRC32 of header fields above
# Total: 16 bytes

def build_header(msg_type: int, payload: bytes, flags: int = 0) -> bytes:
    import zlib
    base = struct.pack('>4sBBHI',
                       MAGIC_BYTES,
                       PROTOCOL_VERSION,
                       msg_type,
                       flags,
                       len(payload))
    crc = zlib.crc32(base) & 0xFFFFFFFF
    return base + struct.pack('>I', crc)


def parse_header(data: bytes) -> dict:
    import zlib
    if len(data) < HEADER_SIZE:
        raise ValueError("Header too short")
    magic, version, msg_type, flags, length = struct.unpack('>4sBBHI', data[:12])
    crc_received, = struct.unpack('>I', data[12:16])
    crc_computed = zlib.crc32(data[:12]) & 0xFFFFFFFF
    if magic != MAGIC_BYTES:
        raise ValueError(f"Invalid magic bytes: {magic.hex()}")
    if version != PROTOCOL_VERSION:
        raise ValueError(f"Unsupported protocol version: {version}")
    if crc_received != crc_computed:
        raise ValueError("Header checksum mismatch")
    return {
        'version': version,
        'msg_type': msg_type,
        'flags': flags,
        'length': length,
    }


# ─────────────────────────────────────────────
# Cryptographic Utilities (no external deps)
# ─────────────────────────────────────────────
def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def derive_session_key(shared_secret: bytes, nonce_client: bytes, nonce_server: bytes) -> bytes:
    """Derive a session key using HKDF-like construction with SHA-256."""
    material = shared_secret + nonce_client + nonce_server
    prk = hmac.new(b'SRCES-v1', material, hashlib.sha256).digest()
    okm = hmac.new(prk, b'session-key\x01', hashlib.sha256).digest()
    return okm[:KEY_SIZE]


def hmac_sign(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_verify(key: bytes, data: bytes, signature: bytes) -> bool:
    expected = hmac_sign(key, data)
    return hmac.compare_digest(expected, signature)


def hash_password(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 password hashing."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)


def xor_encrypt(key: bytes, data: bytes) -> bytes:
    """Stream cipher using SHA-256 keystream (lightweight, no deps)."""
    out = bytearray(len(data))
    keystream = b''
    counter = 0
    for i, byte in enumerate(data):
        if i % 32 == 0:
            block = hashlib.sha256(key + counter.to_bytes(4, 'big')).digest()
            keystream = block
            counter += 1
        out[i] = byte ^ keystream[i % 32]
    return bytes(out)


def xor_decrypt(key: bytes, data: bytes) -> bytes:
    return xor_encrypt(key, data)   # XOR is its own inverse


# ─────────────────────────────────────────────
# Secure Packet Builder / Parser
# ─────────────────────────────────────────────
def build_secure_packet(msg_type: int, payload_dict: dict,
                        session_key: Optional[bytes] = None) -> bytes:
    payload_json = json.dumps(payload_dict).encode()
    if session_key:
        encrypted = xor_encrypt(session_key, payload_json)
        sig = hmac_sign(session_key, encrypted)
        payload = sig + encrypted          # HMAC prefix
        flags = 0x0001                     # encrypted flag
    else:
        payload = payload_json
        flags = 0x0000
    header = build_header(msg_type, payload, flags)
    return header + payload


def parse_secure_packet(data: bytes, session_key: Optional[bytes] = None) -> tuple:
    """Returns (msg_type, payload_dict)."""
    hdr = parse_header(data[:HEADER_SIZE])
    msg_type = hdr['msg_type']
    flags = hdr['flags']
    length = hdr['length']
    payload_raw = data[HEADER_SIZE: HEADER_SIZE + length]
    if flags & 0x0001 and session_key:
        if len(payload_raw) < HMAC_SIZE:
            raise ValueError("Payload too short for HMAC")
        sig = payload_raw[:HMAC_SIZE]
        encrypted = payload_raw[HMAC_SIZE:]
        if not hmac_verify(session_key, encrypted, sig):
            raise ValueError("HMAC verification failed — packet tampered!")
        payload_json = xor_decrypt(session_key, encrypted)
    else:
        payload_json = payload_raw
    payload_dict = json.loads(payload_json)
    return msg_type, payload_dict


def recv_packet(sock) -> bytes:
    """Receive a complete framed packet from socket."""
    header = _recv_exact(sock, HEADER_SIZE)
    hdr = parse_header(header)
    payload = _recv_exact(sock, hdr['length'])
    return header + payload


def _recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf
