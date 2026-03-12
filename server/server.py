#!/usr/bin/env python3
"""
SRCES - Secure Remote Command Execution System
Server Component
"""

import socket
import threading
import subprocess
import time
import uuid
import json
import hashlib
import os
import sys
import signal
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from common.protocol import (
    MsgType, AuthStatus, CmdStatus,
    generate_nonce, derive_session_key, hash_password,
    build_secure_packet, parse_secure_packet, recv_packet,
    NONCE_SIZE
)
from common.audit import get_logger, AuditLogger


# ─────────────────────────────────────────────
# User Database (flat-file, in production use DB)
# ─────────────────────────────────────────────
USERS_FILE = Path(__file__).parent.parent / 'server' / 'users.json'

DEFAULT_USERS = {
    "admin": {
        "salt": "a1b2c3d4e5f60718",
        "password_hash": "",        # set at startup
        "role": "admin",
        "allowed_commands": ["*"],  # wildcard = all
        "max_sessions": 3,
        "failed_attempts": 0,
        "locked": False,
    },
    "operator": {
        "salt": "deadbeefcafebabe",
        "password_hash": "",
        "role": "operator",
        "allowed_commands": ["ls", "pwd", "whoami", "date", "uptime",
                             "df", "free", "ps", "cat", "echo", "hostname"],
        "max_sessions": 2,
        "failed_attempts": 0,
        "locked": False,
    }
}

DEFAULT_PASSWORDS = {"admin": "Admin@1234", "operator": "Oper@5678"}
MAX_FAILED = 5
LOCKOUT_RESET = 300   # seconds


class UserDB:
    def __init__(self):
        self._lock = threading.Lock()
        self._db = {}
        self._load()

    def _load(self):
        if USERS_FILE.exists():
            with open(USERS_FILE) as f:
                self._db = json.load(f)
        else:
            # Bootstrap defaults
            db = {}
            for username, info in DEFAULT_USERS.items():
                salt = bytes.fromhex(info['salt'])
                pw = DEFAULT_PASSWORDS[username]
                ph = hash_password(pw, salt).hex()
                entry = dict(info)
                entry['password_hash'] = ph
                db[username] = entry
            self._db = db
            USERS_FILE.parent.mkdir(exist_ok=True)
            with open(USERS_FILE, 'w') as f:
                json.dump(db, f, indent=2)

    def _save(self):
        with open(USERS_FILE, 'w') as f:
            json.dump(self._db, f, indent=2)

    def authenticate(self, username: str, password: str) -> tuple[bool, str]:
        with self._lock:
            user = self._db.get(username)
            if not user:
                return False, "unknown_user"
            if user.get('locked'):
                return False, "account_locked"
            salt = bytes.fromhex(user['salt'])
            ph = hash_password(password, salt).hex()
            if ph != user['password_hash']:
                user['failed_attempts'] = user.get('failed_attempts', 0) + 1
                if user['failed_attempts'] >= MAX_FAILED:
                    user['locked'] = True
                self._save()
                return False, "invalid_credentials"
            user['failed_attempts'] = 0
            self._save()
            return True, "ok"

    def get_allowed_commands(self, username: str) -> list:
        user = self._db.get(username, {})
        return user.get('allowed_commands', [])

    def is_command_allowed(self, username: str, command: str) -> bool:
        allowed = self.get_allowed_commands(username)
        if '*' in allowed:
            return True
        base_cmd = command.strip().split()[0].split('/')[-1]
        return base_cmd in allowed


# ─────────────────────────────────────────────
# Rate Limiter
# ─────────────────────────────────────────────
class RateLimiter:
    def __init__(self, max_per_minute: int = 10):
        self._max = max_per_minute
        self._windows: dict[str, list] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            times = self._windows.get(key, [])
            times = [t for t in times if now - t < 60]
            if len(times) >= self._max:
                self._windows[key] = times
                return False
            times.append(now)
            self._windows[key] = times
            return True


# ─────────────────────────────────────────────
# Client Session Handler
# ─────────────────────────────────────────────
class ClientSession(threading.Thread):
    def __init__(self, conn: socket.socket, addr: tuple,
                 user_db: UserDB, rate_limiter: RateLimiter,
                 logger: AuditLogger, cmd_timeout: int = 30):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = f"{addr[0]}:{addr[1]}"
        self.user_db = user_db
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.cmd_timeout = cmd_timeout
        self.session_id = str(uuid.uuid4())[:12].upper()
        self.session_key: bytes = b''
        self.username: str = ''
        self.authenticated = False
        self._perf: list[float] = []

    def run(self):
        try:
            if not self._do_auth():
                return
            self.logger.session_open(self.session_id, self.username, self.addr)
            self._command_loop()
        except ConnectionError:
            pass
        except Exception as e:
            self.logger.log('ERROR', session_id=self.session_id,
                            error=str(e), client=self.addr)
        finally:
            self.logger.session_close(self.session_id, self.username)
            self._log_perf_summary()
            try:
                self.conn.close()
            except Exception:
                pass

    # ── Authentication Handshake ─────────────
    def _do_auth(self) -> bool:
        if not self.rate_limiter.is_allowed(self.addr.split(':')[0]):
            self.logger.security_event('RATE_LIMITED', self.addr)
            self._send_raw(MsgType.ERROR, {'code': int(AuthStatus.RATE_LIMITED),
                                           'message': 'Too many auth attempts'})
            return False

        # Step 1: Send challenge (nonce + server nonce)
        server_nonce = generate_nonce()
        self._send_raw(MsgType.AUTH_CHALLENGE, {
            'server_nonce': server_nonce.hex(),
            'methods': ['password'],
        })

        # Step 2: Receive response
        data = recv_packet(self.conn)
        msg_type, payload = parse_secure_packet(data)
        if msg_type != MsgType.AUTH_RESPONSE:
            return False

        username = payload.get('username', '')
        password = payload.get('password', '')
        client_nonce_hex = payload.get('client_nonce', '')

        ok, reason = self.user_db.authenticate(username, password)
        self.logger.auth_attempt(self.addr, username, ok, reason)

        if not ok:
            code = (AuthStatus.ACCOUNT_LOCKED if reason == 'account_locked'
                    else AuthStatus.INVALID_CREDS)
            self._send_raw(MsgType.AUTH_RESULT, {
                'status': int(code),
                'message': reason,
            })
            return False

        # Derive session key
        client_nonce = bytes.fromhex(client_nonce_hex)
        shared_secret = hashlib.sha256(username.encode() + password.encode()).digest()
        self.session_key = derive_session_key(shared_secret, client_nonce, server_nonce)
        self.username = username
        self.authenticated = True

        self._send_raw(MsgType.AUTH_RESULT, {
            'status': int(AuthStatus.SUCCESS),
            'session_id': self.session_id,
            'message': 'Authenticated',
        })
        print(f"  [+] {self.addr} authenticated as '{username}' | session={self.session_id}")
        return True

    # ── Command Loop ─────────────────────────
    def _command_loop(self):
        self.conn.settimeout(SESSION_TIMEOUT := 3600)
        while True:
            data = recv_packet(self.conn)
            msg_type, payload = parse_secure_packet(data, self.session_key)

            if msg_type == MsgType.DISCONNECT:
                break
            elif msg_type == MsgType.KEEPALIVE:
                self._send(MsgType.KEEPALIVE, {'ts': time.time()})
            elif msg_type == MsgType.CMD_REQUEST:
                self._handle_command(payload)
            else:
                self._send(MsgType.ERROR, {'message': 'Unknown message type'})

    def _handle_command(self, payload: dict):
        command = payload.get('command', '').strip()
        req_id = payload.get('req_id', str(uuid.uuid4())[:8])
        timeout = min(payload.get('timeout', 10), self.cmd_timeout)

        if not command:
            self._send(MsgType.CMD_RESPONSE, {
                'req_id': req_id, 'status': int(CmdStatus.ERROR),
                'stderr': 'Empty command', 'stdout': '', 'exit_code': -1,
            })
            return

        if not self.user_db.is_command_allowed(self.username, command):
            self.logger.security_event('CMD_DENIED', self.addr,
                                       f"user={self.username} cmd={command!r}")
            self._send(MsgType.CMD_RESPONSE, {
                'req_id': req_id, 'status': int(CmdStatus.PERMISSION_DENIED),
                'stderr': 'Command not permitted', 'stdout': '', 'exit_code': -2,
            })
            return

        # Execute
        t0 = time.perf_counter()
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout
            )
            duration_ms = (time.perf_counter() - t0) * 1000
            self._perf.append(duration_ms)

            self.logger.command_exec(
                self.session_id, self.username, self.addr,
                command, result.returncode, duration_ms
            )
            self._send(MsgType.CMD_RESPONSE, {
                'req_id': req_id,
                'status': int(CmdStatus.SUCCESS),
                'stdout': result.stdout[:32768],
                'stderr': result.stderr[:4096],
                'exit_code': result.returncode,
                'duration_ms': round(duration_ms, 2),
            })
        except subprocess.TimeoutExpired:
            self._send(MsgType.CMD_RESPONSE, {
                'req_id': req_id, 'status': int(CmdStatus.TIMEOUT),
                'stderr': f'Command timed out after {timeout}s',
                'stdout': '', 'exit_code': -3,
            })
        except Exception as e:
            self._send(MsgType.CMD_RESPONSE, {
                'req_id': req_id, 'status': int(CmdStatus.ERROR),
                'stderr': str(e), 'stdout': '', 'exit_code': -4,
            })

    # ── Helpers ──────────────────────────────
    def _send_raw(self, msg_type: int, payload: dict):
        pkt = build_secure_packet(msg_type, payload)
        self.conn.sendall(pkt)

    def _send(self, msg_type: int, payload: dict):
        pkt = build_secure_packet(msg_type, payload, self.session_key)
        self.conn.sendall(pkt)

    def _log_perf_summary(self):
        if not self._perf:
            return
        avg = sum(self._perf) / len(self._perf)
        mx = max(self._perf)
        mn = min(self._perf)
        self.logger.log('PERF_SUMMARY',
                        session_id=self.session_id,
                        username=self.username,
                        total_commands=len(self._perf),
                        avg_latency_ms=round(avg, 2),
                        max_latency_ms=round(mx, 2),
                        min_latency_ms=round(mn, 2))


# ─────────────────────────────────────────────
# TCP Server
# ─────────────────────────────────────────────
class SRCESServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 9000,
                 max_connections: int = 50):
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.user_db = UserDB()
        self.rate_limiter = RateLimiter(max_per_minute=5)
        self.logger = get_logger()
        self._sock: socket.socket | None = None
        self._running = False
        self._sessions: list[ClientSession] = []

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(self.max_connections)
        self._running = True
        print(f"\n{'='*55}")
        print(f"  SRCES Server v1.0  |  TCP {self.host}:{self.port}")
        print(f"{'='*55}")
        print(f"  Max connections : {self.max_connections}")
        print(f"  Audit log       : {self.logger._path}")
        print(f"  Ready — waiting for connections...\n")
        self.logger.log('SERVER_START', host=self.host, port=self.port)
        try:
            while self._running:
                try:
                    conn, addr = self._sock.accept()
                    print(f"  [→] Connection from {addr[0]}:{addr[1]}")
                    session = ClientSession(conn, addr, self.user_db,
                                           self.rate_limiter, self.logger)
                    self._sessions.append(session)
                    session.start()
                except OSError:
                    break
        finally:
            self._shutdown()

    def _shutdown(self):
        print("\n  [!] Server shutting down...")
        self.logger.log('SERVER_STOP')
        if self._sock:
            self._sock.close()


def main():
    p = argparse.ArgumentParser(description='SRCES Server')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=9000)
    args = p.parse_args()
    srv = SRCESServer(args.host, args.port)
    signal.signal(signal.SIGINT, lambda *_: (setattr(srv, '_running', False),
                                              srv._sock and srv._sock.close()))
    srv.start()


if __name__ == '__main__':
    main()
