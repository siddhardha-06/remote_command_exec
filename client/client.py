#!/usr/bin/env python3
"""
SRCES - Secure Remote Command Execution System
Client Component
"""

import socket
import time
import uuid
import json
import hashlib
import sys
import argparse
import getpass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from common.protocol import (
    MsgType, AuthStatus, CmdStatus,
    generate_nonce, derive_session_key,
    build_secure_packet, parse_secure_packet, recv_packet,
)

BANNER = r"""
  ____  ____   ____ _____  ____
 / ___||  _ \ / ___| ____/ ___|
 \___ \| |_) | |   |  _| \___ \
  ___) |  _ <| |___| |___ ___) |
 |____/|_| \_\\____|_____|____/
 Secure Remote Command Execution System
"""


class SRCESClient:
    def __init__(self, host: str, port: int, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.session_key: bytes = b''
        self.session_id: str = ''
        self._sock: socket.socket | None = None
        self._perf_log: list[dict] = []

    # ── Connection & Auth ────────────────────
    def connect(self, username: str, password: str) -> bool:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        try:
            self._sock.connect((self.host, self.port))
        except ConnectionRefusedError:
            print(f"  [✗] Cannot connect to {self.host}:{self.port}")
            return False

        return self._authenticate(username, password)

    def _authenticate(self, username: str, password: str) -> bool:
        # Step 1: receive challenge
        data = recv_packet(self._sock)
        msg_type, payload = parse_secure_packet(data)
        if msg_type != MsgType.AUTH_CHALLENGE:
            print("  [✗] Unexpected message during handshake")
            return False

        server_nonce = bytes.fromhex(payload['server_nonce'])
        client_nonce = generate_nonce()

        # Step 2: send credentials
        pkt = build_secure_packet(MsgType.AUTH_RESPONSE, {
            'username': username,
            'password': password,
            'client_nonce': client_nonce.hex(),
        })
        self._sock.sendall(pkt)

        # Step 3: receive result
        data = recv_packet(self._sock)
        msg_type, payload = parse_secure_packet(data)
        if msg_type != MsgType.AUTH_RESULT:
            print("  [✗] Unexpected auth result message")
            return False

        status = payload.get('status', -1)
        if status == int(AuthStatus.SUCCESS):
            # Derive session key
            shared_secret = hashlib.sha256(username.encode() + password.encode()).digest()
            self.session_key = derive_session_key(shared_secret, client_nonce, server_nonce)
            self.session_id = payload.get('session_id', '')
            return True
        else:
            print(f"  [✗] Auth failed: {payload.get('message', 'unknown')}")
            return False

    # ── Command Execution ────────────────────
    def execute(self, command: str, timeout: int = 10) -> dict:
        req_id = str(uuid.uuid4())[:8]
        t0 = time.perf_counter()

        pkt = build_secure_packet(MsgType.CMD_REQUEST, {
            'req_id': req_id,
            'command': command,
            'timeout': timeout,
        }, self.session_key)
        self._sock.sendall(pkt)

        data = recv_packet(self._sock)
        msg_type, payload = parse_secure_packet(data, self.session_key)

        rtt_ms = (time.perf_counter() - t0) * 1000
        self._perf_log.append({
            'command': command,
            'rtt_ms': round(rtt_ms, 2),
            'server_exec_ms': payload.get('duration_ms', 0),
            'overhead_ms': round(rtt_ms - payload.get('duration_ms', 0), 2),
        })
        return payload

    def disconnect(self):
        if self._sock:
            try:
                pkt = build_secure_packet(MsgType.DISCONNECT, {}, self.session_key)
                self._sock.sendall(pkt)
            except Exception:
                pass
            self._sock.close()
            self._sock = None

    # ── Performance Report ───────────────────
    def print_perf_report(self):
        if not self._perf_log:
            return
        print(f"\n{'─'*60}")
        print(f"  Performance Overhead Analysis ({len(self._perf_log)} commands)")
        print(f"{'─'*60}")
        print(f"  {'Command':<30} {'RTT':>7} {'Exec':>7} {'Overhead':>9}")
        print(f"  {'─'*28} {'─'*7} {'─'*7} {'─'*9}")
        total_rtt = total_exec = total_ovh = 0
        for p in self._perf_log:
            cmd = p['command'][:28]
            print(f"  {cmd:<30} {p['rtt_ms']:>6.1f}ms {p['server_exec_ms']:>6.1f}ms {p['overhead_ms']:>8.1f}ms")
            total_rtt += p['rtt_ms']
            total_exec += p['server_exec_ms']
            total_ovh += p['overhead_ms']
        n = len(self._perf_log)
        print(f"  {'─'*28} {'─'*7} {'─'*7} {'─'*9}")
        print(f"  {'AVERAGE':<30} {total_rtt/n:>6.1f}ms {total_exec/n:>6.1f}ms {total_ovh/n:>8.1f}ms")
        pct = (total_ovh / total_rtt * 100) if total_rtt else 0
        print(f"\n  Protocol overhead: {total_ovh/n:.1f}ms avg ({pct:.1f}% of RTT)")
        print(f"{'─'*60}\n")


# ─────────────────────────────────────────────
# Interactive Shell
# ─────────────────────────────────────────────
def run_interactive_shell(client: SRCESClient, username: str):
    print(f"\n  Session {client.session_id} | Type 'exit' or 'quit' to disconnect")
    print(f"  Type 'perf' to see performance stats\n")

    while True:
        try:
            line = input(f"  srces[{username}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue
        if line.lower() in ('exit', 'quit', 'logout'):
            break
        if line.lower() == 'perf':
            client.print_perf_report()
            continue
        if line.lower() == 'help':
            print("  Commands: any shell command | perf | exit")
            continue

        result = client.execute(line)
        status = result.get('status', -1)
        stdout = result.get('stdout', '')
        stderr = result.get('stderr', '')
        exit_code = result.get('exit_code', -1)
        exec_ms = result.get('duration_ms', 0)

        if status == int(CmdStatus.PERMISSION_DENIED):
            print(f"  [✗] Permission denied: command not in your allowed list")
        elif status == int(CmdStatus.TIMEOUT):
            print(f"  [✗] Command timed out on server")
        elif status == int(CmdStatus.SUCCESS) or exit_code == 0:
            if stdout:
                for ln in stdout.rstrip().splitlines():
                    print(f"  {ln}")
            if stderr:
                print(f"  [stderr] {stderr.strip()}")
            print(f"  [exit={exit_code} | {exec_ms:.1f}ms]")
        else:
            if stderr:
                print(f"  [✗] {stderr.strip()}")
            print(f"  [exit={exit_code}]")


def main():
    print(BANNER)
    p = argparse.ArgumentParser(description='SRCES Client')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=9000)
    p.add_argument('--user', '-u', default=None)
    p.add_argument('--command', '-c', default=None, help='Run single command')
    args = p.parse_args()

    username = args.user or input("  Username: ").strip()
    password = getpass.getpass("  Password: ")

    client = SRCESClient(args.host, args.port)
    print(f"\n  Connecting to {args.host}:{args.port}...")

    if not client.connect(username, password):
        sys.exit(1)

    print(f"  [✓] Authenticated | session={client.session_id}")

    try:
        if args.command:
            result = client.execute(args.command)
            print(result.get('stdout', ''), end='')
            if result.get('stderr'):
                print(result['stderr'], file=sys.stderr, end='')
            client.print_perf_report()
            sys.exit(result.get('exit_code', 0))
        else:
            run_interactive_shell(client, username)
            client.print_perf_report()
    finally:
        client.disconnect()
        print("  [✓] Disconnected")


if __name__ == '__main__':
    main()
