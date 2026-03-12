"""
SRCES - Audit Logger
Structured, tamper-evident audit trail with HMAC chain.
"""

import json
import time
import hmac
import hashlib
import threading
import os
from pathlib import Path


LOG_DIR = Path(__file__).parent.parent / 'logs'
LOG_DIR.mkdir(exist_ok=True)
AUDIT_LOG = LOG_DIR / 'audit.log'
CHAIN_SECRET = b'srces-audit-chain-secret-v1'   # In prod: load from secure config


class AuditLogger:
    """
    Thread-safe audit logger with HMAC chaining.
    Each entry includes an HMAC over (prev_hash + entry_json)
    making the log tamper-evident.
    """

    def __init__(self, log_path: Path = AUDIT_LOG):
        self._lock = threading.Lock()
        self._path = log_path
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self._path.exists():
            return 'GENESIS'
        with open(self._path, 'r') as f:
            last = None
            for line in f:
                line = line.strip()
                if line:
                    last = line
            if last:
                try:
                    entry = json.loads(last)
                    return entry.get('chain_hash', 'GENESIS')
                except Exception:
                    pass
        return 'GENESIS'

    def _write(self, event_type: str, data: dict):
        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'unix_ts': time.time(),
            'event': event_type,
            **data,
            'prev_hash': self._prev_hash,
        }
        entry_json = json.dumps(entry, separators=(',', ':'))
        chain_input = (self._prev_hash + entry_json).encode()
        chain_hash = hmac.new(CHAIN_SECRET, chain_input, hashlib.sha256).hexdigest()
        entry['chain_hash'] = chain_hash
        final_json = json.dumps(entry, separators=(',', ':'))
        with open(self._path, 'a') as f:
            f.write(final_json + '\n')
        self._prev_hash = chain_hash

    def log(self, event_type: str, **kwargs):
        with self._lock:
            self._write(event_type, kwargs)

    # ── Convenience methods ──────────────────

    def auth_attempt(self, client_addr: str, username: str, success: bool, reason: str = ''):
        self.log('AUTH_ATTEMPT',
                 client=client_addr,
                 username=username,
                 success=success,
                 reason=reason)

    def command_exec(self, session_id: str, username: str, client_addr: str,
                     command: str, exit_code: int, duration_ms: float):
        self.log('CMD_EXEC',
                 session_id=session_id,
                 username=username,
                 client=client_addr,
                 command=command,
                 exit_code=exit_code,
                 duration_ms=round(duration_ms, 2))

    def session_open(self, session_id: str, username: str, client_addr: str):
        self.log('SESSION_OPEN',
                 session_id=session_id,
                 username=username,
                 client=client_addr)

    def session_close(self, session_id: str, username: str, reason: str = 'normal'):
        self.log('SESSION_CLOSE',
                 session_id=session_id,
                 username=username,
                 reason=reason)

    def security_event(self, event: str, client_addr: str, detail: str = ''):
        self.log('SECURITY',
                 event=event,
                 client=client_addr,
                 detail=detail)


def verify_log_integrity(log_path: Path = AUDIT_LOG) -> tuple[bool, list[str]]:
    """
    Verify the HMAC chain of an audit log.
    Returns (is_valid, list_of_errors).
    """
    errors = []
    prev_hash = 'GENESIS'
    with open(log_path, 'r') as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                stored_hash = entry.pop('chain_hash', '')
                entry_json = json.dumps(entry, separators=(',', ':'))
                chain_input = (prev_hash + entry_json).encode()
                expected = hmac.new(CHAIN_SECRET, chain_input, hashlib.sha256).hexdigest()
                if stored_hash != expected:
                    errors.append(f"Line {i}: chain hash mismatch — log may be tampered!")
                else:
                    prev_hash = stored_hash
            except Exception as e:
                errors.append(f"Line {i}: parse error — {e}")
    return len(errors) == 0, errors


# Module-level singleton
_logger = None

def get_logger() -> AuditLogger:
    global _logger
    if _logger is None:
        _logger = AuditLogger()
    return _logger
