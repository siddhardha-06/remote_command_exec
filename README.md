# SRCES — Secure Remote Command Execution System

Lightweight example server/client for remotely running shell commands with a
simple framed protocol, HMAC chaining audit logs, and per-user command ACLs.

## Contents

- `server/` — server implementation and `users.json` (flat-file user DB)
- `client/` — CLI client
- `common/` — protocol and audit utilities
- `test_integration.py` — integration test and benchmark

## Requirements

- Python 3.9+ (annotations use PEP 585 types)
- Works on Windows, Linux, macOS — commands executed on the server host shell

## Quick start

1. Start the server (default host `127.0.0.1`, port `9000`):

```bash
python server/server.py --host 127.0.0.1 --port 9000
```

2. Run the client (interactive shell):

```bash
python client/client.py -u operator
# enter password when prompted
```

3. Run a single command non-interactively:

```bash
python client/client.py -u admin -c "hostname"
```

4. Run the integration tests (starts a temporary server on port 19999):

```bash
python test_integration.py
```

## Default accounts

- `admin` — password `Admin@1234` (full access)
- `operator` — password `Oper@5678` (restricted)

Passwords are set from `server/server.py` defaults when `server/users.json`
is missing; the file stores salted PBKDF2 hashes after first run.

## User ACLs

Per-user allowed commands live in `server/users.json` as `allowed_commands`.
The server checks the base command (first token) against that list. To allow a
command for a user, add its base name to their `allowed_commands` array and
restart the server.


## Troubleshooting

- If a command is rejected, check `server/users.json` `allowed_commands` for
  the account. On Windows some Unix commands (e.g. `uptime`) are unavailable —
  use PowerShell or Windows equivalents.
- If an account is locked, set `failed_attempts: 0` and `locked: false` in
  `server/users.json` and restart the server.

## Firewall / Networking

If the server is running on a machine with a host firewall, you may need to
open the TCP port the server listens on (default `9000`). On Windows run an
elevated (Administrator) Command Prompt and execute:

```powershell
netsh advfirewall firewall add rule name="SRCES" protocol=TCP dir=in localport=9000 action=allow
```

On Linux systems using `ufw`:

```bash
sudo ufw allow 9000/tcp
```

Security note: only open the port if you trust the network and understand the
risks — prefer firewall rules restricting source IP ranges or running the
service behind a secure VPN/TLS tunnel.

## Development notes

- Protocol framing and packet handling are in `common/protocol.py`.
- Audit logging and verification are in `common/audit.py`.
- The integration test exercises authentication, ACLs, encryption, and logs.

---
