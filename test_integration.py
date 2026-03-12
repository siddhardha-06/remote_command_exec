#!/usr/bin/env python3
"""
SRCES Integration Test & Performance Benchmark
Runs server in background, exercises all features, prints report.
"""
import sys, threading, time, socket, subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from client.client import SRCESClient
from server.server import SRCESServer

PORT = 19999
HOST = '127.0.0.1'

PASS  = '\033[92m✓\033[0m'
FAIL  = '\033[91m✗\033[0m'
WARN  = '\033[93m!\033[0m'

results = []

def check(label, condition, detail=''):
    mark = PASS if condition else FAIL
    results.append(condition)
    print(f"  [{mark}] {label}" + (f"  →  {detail}" if detail else ''))


def start_server():
    srv = SRCESServer(HOST, PORT)
    t = threading.Thread(target=srv.start, daemon=True)
    t.start()
    time.sleep(0.4)
    return srv


def wait_port(host, port, timeout=5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection((host, port), 0.2)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def run_tests():
    print("\n" + "="*58)
    print("  SRCES Integration Test Suite")
    print("="*58)

    # ── Start server ─────────────────────────
    print("\n  [*] Starting server on port", PORT)
    srv = start_server()
    up = wait_port(HOST, PORT)
    check("Server starts and listens on TCP port", up)
    if not up:
        print("  Server failed to start. Aborting.")
        return

    # ── Test 1: Valid authentication ─────────
    print("\n  [*] Test: Authentication")
    c = SRCESClient(HOST, PORT)
    ok = c.connect('admin', 'Admin@1234')
    check("Admin login with correct credentials", ok)
    if ok:
        check("Session key derived (non-empty)", len(c.session_key) == 32,
              f"{len(c.session_key)} bytes")
        check("Session ID assigned", bool(c.session_id), c.session_id)
        c.disconnect()

    # ── Test 2: Bad credentials ───────────────
    print("\n  [*] Test: Reject bad credentials")
    c2 = SRCESClient(HOST, PORT)
    ok2 = c2.connect('admin', 'wrongpassword')
    check("Bad password rejected", not ok2)

    # ── Test 3: Command execution ─────────────
    print("\n  [*] Test: Command Execution (admin)")
    c3 = SRCESClient(HOST, PORT)
    c3.connect('admin', 'Admin@1234')
    r = c3.execute('echo hello_srces')
    check("Command executes successfully",
          r.get('exit_code') == 0,
          f"exit={r.get('exit_code')}")
    check("Output contains expected string",
          'hello_srces' in r.get('stdout', ''),
          repr(r.get('stdout', '').strip()))
    check("Server-side exec time reported",
          r.get('duration_ms', -1) >= 0,
          f"{r.get('duration_ms')}ms")

    # ── Test 4: Operator command restriction ──
    print("\n  [*] Test: Command ACL (operator)")
    c4 = SRCESClient(HOST, PORT)
    c4.connect('operator', 'Oper@5678')
    r_allowed = c4.execute('echo allowed')
    r_denied  = c4.execute('rm -rf /tmp/test_srces')
    from common.protocol import CmdStatus
    check("Operator: allowed command executes",
          r_allowed.get('exit_code') == 0)
    check("Operator: disallowed command denied",
          r_denied.get('status') == int(CmdStatus.PERMISSION_DENIED),
          f"status={r_denied.get('status')}")

    # ── Test 5: Packet integrity ──────────────
    print("\n  [*] Test: Encrypted session packets")
    r2 = c3.execute('hostname')
    check("Encrypted command/response roundtrip",
          r2.get('exit_code') == 0)

    # ── Test 6: Performance overhead ─────────
    print("\n  [*] Performance Overhead Analysis")
    commands = ['echo perf', 'date', 'uptime', 'pwd', 'whoami']
    for cmd in commands:
        c3.execute(cmd)
    c4_cmds = ['echo 1', 'date', 'pwd', 'hostname', 'uptime']
    for cmd in c4_cmds:
        c4.execute(cmd)

    perfs = c3._perf_log
    if perfs:
        avg_ovh = sum(p['overhead_ms'] for p in perfs) / len(perfs)
        avg_rtt = sum(p['rtt_ms'] for p in perfs) / len(perfs)
        pct = avg_ovh / avg_rtt * 100 if avg_rtt else 0
        check(f"Protocol overhead < 50% of RTT",
              pct < 50,
              f"{pct:.1f}% ({avg_ovh:.1f}ms overhead of {avg_rtt:.1f}ms RTT)")

    c3.disconnect()
    c4.disconnect()

    # ── Test 7: Audit log ─────────────────────
    print("\n  [*] Test: Audit Log Integrity")
    from common.audit import verify_log_integrity, AUDIT_LOG
    time.sleep(0.1)
    if AUDIT_LOG.exists():
        ok_log, errors = verify_log_integrity(AUDIT_LOG)
        check("Audit log HMAC chain is valid", ok_log,
              f"{len(errors)} errors" if errors else "all entries verified")
    else:
        check("Audit log created", False, "file not found")

    # ── Summary ───────────────────────────────
    print("\n" + "="*58)
    passed = sum(results)
    total  = len(results)
    print(f"  Results: {passed}/{total} tests passed")
    if passed == total:
        print(f"  \033[92mAll tests passed!\033[0m")
    else:
        print(f"  \033[91m{total-passed} test(s) failed\033[0m")
    print("="*58 + "\n")

    # Print perf table
    print("  Performance breakdown (admin session):")
    if c3._perf_log:
        print(f"  {'Command':<20} {'RTT':>7} {'Exec':>7} {'Overhead':>9}")
        print(f"  {'─'*20} {'─'*7} {'─'*7} {'─'*9}")
        for p in c3._perf_log:
            cmd = p['command'][:18]
            print(f"  {cmd:<20} {p['rtt_ms']:>6.1f}ms {p['server_exec_ms']:>6.1f}ms {p['overhead_ms']:>8.1f}ms")
    print()


if __name__ == '__main__':
    run_tests()
