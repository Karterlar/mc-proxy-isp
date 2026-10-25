"""Isolated tests. The committed TLS key is public TEST DATA, never production."""
import base64
import http.client
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import relay

FIXTURES = Path(__file__).parent / "test-fixtures"


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(60)
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except OSError:
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mc-relay-test-")
        self.directory = Path(self.temp.name)
        self.store = relay.Store(self.directory / "accounts.json")
        self.password = self.store.create("alice", max_tunnels=2)
        self.other_password = self.store.create("bob")
        self.echo = EchoServer(("127.0.0.1", 0), Echo)
        self.echo_thread = threading.Thread(target=self.echo.serve_forever, daemon=True)
        self.echo_thread.start()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(FIXTURES / "test-cert.pem", FIXTURES / "test-key.pem")
        self.connections = []
        self.resolutions = []

        def resolver(host, port):
            self.resolutions.append((host, port))
            if host in ("isp.example", "second.example"):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, ("8.8.8.8", port))]
            return relay.resolve_public(host, port)

        def connector(target):
            resolver(target["host"], target["port"])
            self.connections.append(dict(target))
            return socket.create_connection(self.echo.server_address, timeout=2)

        self.server = relay.RelayServer(("127.0.0.1", 0), context, self.store, connector=connector, resolver=resolver, marker="fixture-marker", idle_timeout=30)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client_context = ssl.create_default_context(cafile=str(FIXTURES / "test-cert.pem"))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.echo.shutdown()
        self.echo.server_close()
        self.thread.join(timeout=2)
        self.echo_thread.join(timeout=2)
        self.temp.cleanup()

    def auth(self, username="alice", password=None):
        return "Basic " + base64.b64encode((username + ":" + (password or self.password)).encode()).decode()

    def api(self, method="GET", path="/v1/status", body=None, username="alice", password=None):
        connection = http.client.HTTPSConnection("localhost", self.server.server_port, context=self.client_context, timeout=3)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(("127.0.0.1", address[1]), timeout, source_address)
        headers = {"Authorization": self.auth(username, password), "Content-Type": "application/json"}
        connection.request(method, path, None if body is None else json.dumps(body), headers)
        response = connection.getresponse()
        status, payload = response.status, json.loads(response.read())
        connection.close()
        return status, payload

    def bind(self, host="isp.example", port=12345, revision=None, username="alice", password=None):
        body = {"host": host, "port": port}
        if revision is not None:
            body["expectedRevision"] = revision
        return self.api("POST", "/v1/upstream", body, username, password)

    def tunnel(self, destination="isp.example:12345", auth=None, pipelined=b""):
        connection = self.client_context.wrap_socket(socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3), server_hostname="localhost")
        connection.sendall((f"CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\nProxy-Authorization: {auth or self.auth()}\r\n\r\n").encode() + pipelined)
        headers = b""
        while not headers.endswith(b"\r\n\r\n"):
            headers += connection.recv(1)
        return connection, int(headers.split(b" ")[1])

    def test_health_requires_no_credentials_and_no_forward_proxy(self):
        connection = http.client.HTTPSConnection("localhost", self.server.server_port, context=self.client_context)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(("127.0.0.1", address[1]), timeout, source_address)
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read())["marker"], "fixture-marker")
        connection.close()
        self.assertEqual(self.api(path="http://example.com/")[0], 404)
        self.assertEqual(self.connections, [])

    def test_tls_certificate_must_be_trusted(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            with socket.create_connection(self.server.server_address, timeout=2) as raw:
                ssl.create_default_context().wrap_socket(raw, server_hostname="localhost")

    def test_status_before_binding_and_no_secret_disclosure(self):
        status, payload = self.api()
        self.assertEqual(status, 200)
        self.assertIsNone(payload["upstream"])
        self.assertEqual(payload["bindingRevision"], 0)
        self.assertNotIn(self.password, json.dumps(payload))
        self.assertNotIn("passwordHash", payload)
        self.assertNotIn(self.password, self.store.path.read_text())

    def test_wrong_credentials_api_and_connect(self):
        self.assertEqual(self.api(password="incorrect-password-1234567890")[0], 401)
        sock, status = self.tunnel(auth=self.auth(password="incorrect-password-1234567890"))
        sock.close()
        self.assertEqual(status, 407)
        self.assertEqual(self.connections, [])

    def test_unbound_or_wrong_destination_denied(self):
        sock, status = self.tunnel()
        sock.close()
        self.assertEqual(status, 403)
        self.bind()
        sock, status = self.tunnel("second.example:12345")
        sock.close()
        self.assertEqual(status, 403)
        self.assertEqual(self.connections, [])

    def test_real_tls_connect_bidirectional_binary_and_pipelined(self):
        self.assertEqual(self.bind()[0], 200)
        payload = bytes(range(256)) * 512
        sock, status = self.tunnel(pipelined=payload[:1024])
        self.assertEqual(status, 200)
        sock.sendall(payload[1024:])
        received = b""
        while len(received) < len(payload):
            received += sock.recv(65536)
        sock.close()
        self.assertEqual(received, payload)
        self.assertEqual(self.connections, [{"host": "isp.example", "port": 12345}])

    def test_account_isolation(self):
        self.bind()
        self.assertEqual(self.api(username="bob", password=self.other_password)[1]["upstream"], None)
        sock, status = self.tunnel(auth=self.auth("bob", self.other_password))
        sock.close()
        self.assertEqual(status, 403)
        self.bind("second.example", username="bob", password=self.other_password)
        self.assertEqual(self.api()[1]["upstream"]["host"], "isp.example")

    def test_tunnel_limit_and_release(self):
        self.bind()
        one, first = self.tunnel()
        two, second = self.tunnel()
        three, third = self.tunnel()
        three.close()
        self.assertEqual((first, second, third), (200, 200, 429))
        one.close()
        two.close()
        for _ in range(30):
            if self.api()[1]["activeTunnels"] == 0:
                break
            time.sleep(.05)
        self.assertEqual(self.api()[1]["activeTunnels"], 0)

    def test_active_binding_update_refused_but_identical_idempotent(self):
        self.assertEqual(self.bind(revision=0)[1]["bindingRevision"], 1)
        sock, _ = self.tunnel()
        self.assertEqual(self.bind("second.example", revision=1)[0], 409)
        self.assertEqual(self.bind(revision=1)[1]["bindingRevision"], 1)
        self.assertEqual(self.api("DELETE", "/v1/upstream", {"expectedRevision": 1})[0], 409)
        sock.sendall(b"still-open")
        self.assertEqual(sock.recv(10), b"still-open")
        sock.close()

    def test_stale_compare_and_swap_does_not_overwrite_other_client(self):
        self.assertEqual(self.bind(revision=0)[1]["bindingRevision"], 1)
        self.assertEqual(self.bind("second.example", revision=1)[1]["bindingRevision"], 2)
        status, body = self.bind(revision=1)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "binding_revision_conflict")
        self.assertEqual(self.api("DELETE", "/v1/upstream", {"expectedRevision": 1})[0], 409)
        self.assertEqual(self.api()[1]["upstream"]["host"], "second.example")
        self.assertEqual(self.api("DELETE", "/v1/upstream", {"expectedRevision": 2})[1]["bindingRevision"], 3)
        self.assertIsNone(self.api()[1]["upstream"])
        self.assertEqual(self.api("DELETE", "/v1/upstream", {"expectedRevision": 3})[1]["bindingRevision"], 3)

    def test_disable_revokes_open_tunnel_and_cached_auth(self):
        self.bind()
        sock, status = self.tunnel()
        self.assertEqual(status, 200)
        self.store.disable("alice")
        self.assertEqual(sock.recv(1), b"")
        sock.close()
        self.assertEqual(self.api()[0], 401)
        self.assertEqual(self.api(username="bob", password=self.other_password)[0], 200)

    def test_private_binding_and_dns_rebinding_refused(self):
        for host in ("127.0.0.1", "169.254.169.254", "10.1.2.3", "::1"):
            self.assertEqual(self.bind(host)[0], 403)
        self.assertIsNone(self.api()[1]["upstream"])
        self.bind()
        self.server.connector = lambda target: relay.connect_public(target)
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 12345))]
        with patch("relay.socket.getaddrinfo", return_value=fake):
            # Client connect uses an already numerical sockaddr through socket.socket.
            raw = socket.socket()
            raw.settimeout(3)
            raw.connect(self.server.server_address)
            sock = self.client_context.wrap_socket(raw, server_hostname="localhost")
            sock.sendall(("CONNECT isp.example:12345 HTTP/1.1\r\nProxy-Authorization: " + self.auth() + "\r\n\r\n").encode())
            self.assertTrue(sock.recv(1024).startswith(b"HTTP/1.1 403 "))
            sock.close()

    def test_idle_tunnel_closes(self):
        self.server.idle_timeout = .15
        self.bind()
        sock, status = self.tunnel()
        self.assertEqual(status, 200)
        self.assertEqual(sock.recv(1), b"")
        sock.close()

    def test_fragmented_json_body_is_fully_read(self):
        sock = self.client_context.wrap_socket(socket.create_connection(self.server.server_address), server_hostname="localhost")
        body = b'{"host":"isp.example","port":12345,"expectedRevision":0}'
        sock.sendall((f"POST /v1/upstream HTTP/1.1\r\nAuthorization: {self.auth()}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body[:8])
        time.sleep(.05)
        sock.sendall(body[8:])
        self.assertTrue(sock.recv(1024).startswith(b"HTTP/1.1 200 "))
        sock.close()

    def test_invalid_json_schema_cannot_change_binding(self):
        for body in ({"host": "isp.example", "port": True}, {"host": "isp.example", "port": 12345, "password": "no"}, {"host": "isp.example", "port": 12345, "expectedRevision": True}):
            self.assertEqual(self.api("POST", "/v1/upstream", body)[0], 400)
        self.assertIsNone(self.api()[1]["upstream"])


class PureTests(unittest.TestCase):
    def test_address_allowlist(self):
        for value in ("127.0.0.1", "0.0.0.0", "10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.169.254", "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::", "::1", "fe80::1", "fc00::1", "fec0::1", "2001:db8::1", "ff02::1", "::ffff:8.8.8.8", "64:ff9b::a00:1", "2002:0808:0808::1"):
            self.assertFalse(relay.public_address(value), value)
        for value in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertTrue(relay.public_address(value), value)

    def test_mixed_public_private_dns_answers_rejected(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.1.1", 443))]
        with patch("relay.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(PermissionError):
                relay.resolve_public("isp.example", 443)

    def test_numeric_sockaddr_used_after_single_resolution(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 12345))]
        with patch("relay.socket.getaddrinfo", return_value=answers) as resolve, patch("relay.socket.socket") as create:
            relay.connect_public({"host": "isp.example", "port": 12345})
            resolve.assert_called_once()
            create.return_value.connect.assert_called_once_with(("8.8.8.8", 12345))

    def test_host_authority_validation(self):
        self.assertEqual(relay.authority("ISP.EXAMPLE.:12345"), {"host": "isp.example", "port": 12345})
        self.assertEqual(relay.authority("[2606:4700:4700::1111]:443")["port"], 443)
        for value in ("http://example.com:443", "user@example.com:443", "127.0.0.1:0", "example.com:65536", "example.com:443/path", "fe80::1%eth0:443", "example.com:443\r\nInjected:1"):
            with self.assertRaises(ValueError, msg=value):
                relay.authority(value)

    def test_atomic_store_replace_failure_keeps_old_complete_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.json"
            store = relay.Store(path)
            store.create("alice")
            before = path.read_bytes()
            with patch("relay.os.replace", side_effect=OSError("injected_replace_failure")):
                with self.assertRaises(OSError):
                    store.disable("alice")
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(Path(directory).glob(".relay-*")), [])

    def test_cli_enrollment_secret_only_in_file_and_revoke(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            if os.name != "nt":
                path.chmod(0o700)
            state, output = path / "accounts.json", path / "enrollment.json"
            command = [sys.executable, str(Path(__file__).parent / "manage.py"), "--state", str(state), "create", "fixture", "--host", "192.0.2.44", "--cert", str(FIXTURES / "test-cert.pem"), "--server-name", "localhost", "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            enrolled = json.loads(output.read_text())
            self.assertNotIn(enrolled["password"], result.stdout + result.stderr)
            self.assertNotIn(enrolled["password"], state.read_text())
            self.assertEqual(len(enrolled["certificateSha256"]), 64)
            self.assertIn("BEGIN CERTIFICATE", enrolled["certificate"])
            if os.name != "nt":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            again = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            disabled = subprocess.run([sys.executable, str(Path(__file__).parent / "manage.py"), "--state", str(state), "disable", "fixture"], capture_output=True, text=True)
            self.assertEqual(disabled.returncode, 0)
            self.assertFalse(relay.Store(state).account("fixture")["enabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
