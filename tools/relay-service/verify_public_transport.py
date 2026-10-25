#!/usr/bin/env python3
"""Explicit no-ISP acceptance via two public IP-check services; CAS cleanup."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import io
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import sys
import time

TARGETS = ("api.ipify.org", "checkip.amazonaws.com")


class InnerTLS:
    """Verified target TLS records transported inside an existing relay TLS socket."""
    def __init__(self, transport, hostname):
        self.transport = transport
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=False, server_hostname=hostname)
        self.run(self.tls.do_handshake)

    def flush(self):
        while self.outgoing.pending:
            self.transport.sendall(self.outgoing.read())

    def run(self, operation):
        while True:
            try:
                result = operation()
                self.flush()
                return result
            except ssl.SSLWantWriteError:
                self.flush()
            except ssl.SSLWantReadError:
                self.flush()
                data = self.transport.recv(65536)
                if data:
                    self.incoming.write(data)
                else:
                    self.incoming.write_eof()

    def sendall(self, data):
        view = memoryview(data)
        while view:
            count = self.run(lambda: self.tls.write(view))
            view = view[count:]

    def recv(self, count):
        try:
            return self.run(lambda: self.tls.read(count))
        except ssl.SSLZeroReturnError:
            return b""

    def makefile(self, mode):
        owner = self

        class Reader(io.RawIOBase):
            def readable(self):
                return True

            def readinto(self, buffer):
                data = owner.recv(len(buffer))
                buffer[:len(data)] = data
                return len(data)

        return io.BufferedReader(Reader())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("enrollment")
    parser.add_argument("--expected-vps-ip", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    enrollment = json.loads(Path(args.enrollment).read_text(encoding="utf-8"))
    expected = str(ipaddress.ip_address(args.expected_vps_ip))
    context = ssl.create_default_context(cadata=enrollment["certificate"])
    context.set_alpn_protocols(["http/1.1"])
    pin = enrollment["certificateSha256"].replace(":", "").upper()
    auth = "Basic " + base64.b64encode((enrollment["username"] + ":" + enrollment["password"]).encode()).decode()

    def outer():
        raw = socket.create_connection((enrollment["host"], enrollment["port"]), timeout=20)
        try:
            connection = context.wrap_socket(raw, server_hostname=enrollment["tlsServerName"])
            observed = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest().upper()
            if observed != pin:
                connection.close()
                raise ValueError("relay_certificate_pin_mismatch")
            return connection
        except Exception:
            raw.close()
            raise

    def api(method="GET", body=None):
        path = "/v1/status" if method == "GET" else "/v1/upstream"
        payload = b"" if body is None else json.dumps(body).encode()
        headers = [f"{method} {path} HTTP/1.1", "Host: " + enrollment["tlsServerName"], "Authorization: " + auth,
                   "Connection: close", "Content-Type: application/json", "Content-Length: " + str(len(payload))]
        with outer() as connection:
            connection.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + payload)
            response = http.client.HTTPResponse(connection)
            response.begin()
            result = json.loads(response.read(8192))
            if response.status != 200:
                raise RuntimeError("relay_api_" + str(response.status) + "_" + str(result.get("error", "unknown")))
            return result

    def idle(expected_revision=None):
        for _ in range(40):
            state = api()
            if expected_revision is not None and state["bindingRevision"] != expected_revision:
                raise RuntimeError("binding_changed_by_another_client")
            if state["activeTunnels"] == 0:
                return state
            time.sleep(.25)
        raise RuntimeError("active_tunnels_did_not_drain")

    result = {"startedAt": datetime.now(timezone.utc).isoformat(), "relayHost": enrollment["host"], "relayPort": enrollment["port"],
              "expectedVpsExitIp": expected, "tests": [], "scope": "TLS client -> VPS CONNECT -> public IP service; no ISP involved",
              "ispChainVerified": False, "localNetworkOrIspConfigChanged": False, "secretsIncluded": False,
              "relayCertificateSha256": pin, "targetTlsCertificateValidation": True}
    owned_revision = None
    try:
        initial = idle()
        result["initialBinding"] = initial["upstream"]
        result["initialRevision"] = initial["bindingRevision"]
        if initial["upstream"] is not None:
            raise RuntimeError("initial_binding_is_not_null_no_changes_made")
        for hostname in TARGETS:
            state = idle(owned_revision)
            binding = api("POST", {"host": hostname, "port": 443, "expectedRevision": state["bindingRevision"]})
            owned_revision = binding["bindingRevision"]
            check = {"target": hostname, "port": 443, "bindingRevision": owned_revision}
            result["tests"].append(check)
            try:
                with outer() as connection:
                    request = f"CONNECT {hostname}:443 HTTP/1.1\r\nHost: {hostname}:443\r\nProxy-Authorization: {auth}\r\n\r\n"
                    connection.sendall(request.encode())
                    headers = b""
                    while not headers.endswith(b"\r\n\r\n"):
                        piece = connection.recv(1)
                        if not piece or len(headers) > 16384:
                            raise RuntimeError("invalid_connect_response")
                        headers += piece
                    check["connectStatus"] = int(headers.split(b" ")[1])
                    if check["connectStatus"] != 200:
                        raise RuntimeError("connect_refused")
                    inner = InnerTLS(connection, hostname)
                    check["targetTlsVersion"] = inner.tls.version()
                    inner.sendall(f"GET / HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: MC-Proxy-Transport-Acceptance/1\r\nAccept: text/plain\r\nConnection: close\r\n\r\n".encode())
                    response = http.client.HTTPResponse(inner)
                    response.begin()
                    body = response.read(4096).decode("ascii").strip()
                    check["httpStatus"] = response.status
                    if response.status != 200:
                        raise RuntimeError("public_ip_service_http_failure")
                    observed = str(ipaddress.ip_address(body))
                    check["observedExitIp"] = observed
                    check["matchesExpectedVpsExit"] = observed == expected
                    check["passed"] = observed == expected
            except Exception as error:
                check["passed"] = False
                check["errorType"] = type(error).__name__
            idle(owned_revision)
    except Exception as error:
        result["workflowErrorType"] = type(error).__name__
        # Deliberately do not render exception messages or raw requests.
    finally:
        if owned_revision is not None:
            try:
                idle(owned_revision)
                cleared = api("DELETE", {"expectedRevision": owned_revision})
                result["cleanupClearedBinding"] = cleared["upstream"] is None
                result["finalRevision"] = cleared["bindingRevision"]
            except Exception as error:
                result["cleanupClearedBinding"] = False
                result["cleanupErrorType"] = type(error).__name__
                result["cleanupDidNotOverrideExternalRevision"] = True
        try:
            final = api()
            result["finalBinding"] = final["upstream"]
            result["finalRevision"] = final["bindingRevision"]
            result["finalActiveTunnels"] = final["activeTunnels"]
        except Exception as error:
            result["finalStatusErrorType"] = type(error).__name__
        result["finishedAt"] = datetime.now(timezone.utc).isoformat()
        result["passed"] = len(result["tests"]) == len(TARGETS) and all(item.get("passed") for item in result["tests"]) and result.get("cleanupClearedBinding") is True and result.get("finalActiveTunnels") == 0
        serialized = json.dumps(result, indent=2) + "\n"
        Path(args.output).write_text(serialized, encoding="utf-8")
        print(serialized, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print("Public transport acceptance failed: " + type(error).__name__ + ". No credentials were printed.", file=sys.stderr)
        raise SystemExit(1)
