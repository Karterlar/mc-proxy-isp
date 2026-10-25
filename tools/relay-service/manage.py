#!/usr/bin/env python3
"""Local operator CLI. Passwords are generated and only written to private files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import sys

from relay import Store, atomic_json, normalize_host


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default="/var/lib/mc-proxy-relay/accounts.json")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("username")
    create.add_argument("--host", required=True)
    create.add_argument("--port", type=int, default=443)
    create.add_argument("--server-name", default="proxypilot-relay-test.local")
    create.add_argument("--cert", default="/etc/proxypilot-relay-health/server-cert.pem")
    create.add_argument("--output", required=True)
    create.add_argument("--max-tunnels", type=int, default=64)
    disable = commands.add_parser("disable")
    disable.add_argument("username")
    commands.add_parser("list")
    args = parser.parse_args()
    os.umask(0o077)
    store = Store(args.state)
    if args.command == "create":
        output = Path(args.output).absolute()
        if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
            parser.error("Output must be a new file in an existing private directory.")
        if os.name != "nt" and output.parent.stat().st_mode & 0o077:
            parser.error("Enrollment output directory must have mode 0700.")
        host, name = normalize_host(args.host), normalize_host(args.server_name)
        if not 1 <= args.port <= 65535:
            parser.error("Invalid relay port.")
        certificate = Path(args.cert).read_text(encoding="ascii")
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest().upper()
        # Validate certificate before committing the new account.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=certificate)
        password = store.create(args.username, max_tunnels=args.max_tunnels)
        try:
            atomic_json(output, {"version": 1, "type": "mc-proxy-relay", "host": host, "port": args.port,
                                 "tlsServerName": name, "certificateSha256": fingerprint, "certificate": certificate,
                                 "username": args.username, "password": password})
        except Exception:
            # A lost enrollment must not leave a usable account with unknown credentials.
            store.disable(args.username)
            raise
        print("Account created. Enrollment written to the requested private file; no credentials printed.")
    elif args.command == "disable":
        store.disable(args.username)
        print("Account disabled. Existing tunnels close on their next liveness check (normally within 1 second).")
    else:
        print(json.dumps({"accounts": [{"username": name, "enabled": account.get("enabled", False),
                                       "maxTunnels": account.get("maxTunnels"), "upstream": account.get("upstream")}
                                      for name, account in store.read()["accounts"].items()]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError):
        print("Operation failed; inspect local file permissions and account options. Credentials were not printed.", file=sys.stderr)
        raise SystemExit(1)
