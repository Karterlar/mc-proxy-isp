#!/usr/bin/env python3
"""Read-only deployed relay acceptance. No ISP registration or credential output."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("enrollment")
    parser.add_argument("--output")
    parser.add_argument("--connect-host")
    args = parser.parse_args()
    enrollment = json.loads(Path(args.enrollment).read_text(encoding="utf-8"))
    context = ssl.create_default_context(cadata=enrollment["certificate"])
    host = args.connect_host or enrollment["host"]
    pin = enrollment["certificateSha256"].replace(":", "").upper()
    good = "Basic " + base64.b64encode((enrollment["username"] + ":" + enrollment["password"]).encode()).decode()
    wrong = "Basic " + base64.b64encode((enrollment["username"] + ":" + "deliberately-incorrect-acceptance-password").encode()).decode()
    observed_pins = set()

    def request(method, target, auth=None, proxy=False):
        with socket.create_connection((host, enrollment["port"]), timeout=15) as raw:
            with context.wrap_socket(raw, server_hostname=enrollment["tlsServerName"]) as connection:
                observed = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest().upper()
                if observed != pin:
                    raise ValueError("certificate_pin_mismatch")
                observed_pins.add(observed)
                headers = [f"{method} {target} HTTP/1.1", "Host: " + enrollment["tlsServerName"], "Connection: close"]
                if auth:
                    headers.append(("Proxy-Authorization: " if proxy else "Authorization: ") + auth)
                connection.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
                response = http.client.HTTPResponse(connection)
                response.begin()
                payload = response.read(8192)
                return response.status, json.loads(payload)

    checks = []
    status, health = request("GET", "/healthz")
    checks.append({"check": "trusted_tls_health", "status": status, "passed": status == 200 and health.get("service") == "mc-proxy-relay" and health.get("status") == "ok"})
    status, account = request("GET", "/v1/status", good)
    checks.append({"check": "authenticated_status_initially_unbound", "status": status,
                   "passed": status == 200 and account.get("ok") is True and account.get("upstream") is None and account.get("activeTunnels") == 0})
    for name, method, target, auth, proxy, expected in [
        ("unauthenticated_api_denied", "GET", "/v1/status", None, False, 401),
        ("incorrect_api_password_denied", "GET", "/v1/status", wrong, False, 401),
        ("unauthenticated_connect_denied", "CONNECT", "example.com:443", None, True, 407),
        ("incorrect_connect_password_denied", "CONNECT", "example.com:443", wrong, True, 407),
        ("unbound_authenticated_connect_denied", "CONNECT", "example.com:443", good, True, 403),
        ("ordinary_forward_proxy_denied", "GET", "http://example.com/", good, False, 404),
    ]:
        status, _ = request(method, target, auth, proxy)
        checks.append({"check": name, "status": status, "passed": status == expected})
    result = {"verifiedAt": datetime.now(timezone.utc).isoformat(), "host": enrollment["host"], "port": enrollment["port"],
              "tlsServerName": enrollment["tlsServerName"], "certificateSha256": pin, "certificatePinVerified": observed_pins == {pin},
              "account": enrollment["username"], "upstream": account.get("upstream"), "bindingRevision": account.get("bindingRevision"),
              "activeTunnels": account.get("activeTunnels"), "maxTunnels": account.get("maxTunnels"), "checks": checks,
              "passed": all(item["passed"] for item in checks), "mutatedBinding": False, "ispChainVerified": False,
              "secretsIncluded": False, "transport": "native TLS sockets; environment HTTP proxy variables are not used"}
    serialized = json.dumps(result, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print("Relay acceptance failed: " + type(error).__name__ + ". No credentials were printed.", file=sys.stderr)
        raise SystemExit(1)
