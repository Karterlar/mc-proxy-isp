#!/usr/bin/env python3
"""MC Proxy private TLS CONNECT relay. Python 3.12+, standard library only.

Relay accounts never receive ISP credentials. Each account can tunnel only to its
registered public upstream endpoint. No general HTTP forwarding is implemented.
"""
import argparse
import base64
import contextlib
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import ssl
import tempfile
import threading
import time

USER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$")
MAX_BODY = 2048


def normalize_host(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("invalid_host")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if any(c.isspace() for c in value) or any(c in value for c in "/\\%@?#"):
        raise ValueError("invalid_host")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        if ":" in value:
            raise ValueError("invalid_host") from None
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        raise ValueError("invalid_host")
    return value


def endpoint(data):
    if not isinstance(data, dict) or set(data) != {"host", "port"}:
        raise ValueError("invalid_upstream")
    port = data["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("invalid_port")
    return {"host": normalize_host(data["host"]), "port": port}


def authority(value):
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:([0-9]{1,5})", value)
    else:
        match = re.fullmatch(r"([^:]+):([0-9]{1,5})", value)
    if not match:
        raise ValueError("invalid_authority")
    return endpoint({"host": match[1], "port": int(match[2])})


def public_address(value):
    address = ipaddress.ip_address(value.split("%", 1)[0])
    if not address.is_global or address.is_multicast or address.is_unspecified:
        return False
    if address.version == 6:
        if address.ipv4_mapped or address.sixtofour or address.teredo or address.is_site_local:
            return False
        # Do not permit NAT64 to smuggle a private IPv4 destination.
        if address in ipaddress.ip_network("64:ff9b::/96") or address in ipaddress.ip_network("64:ff9b:1::/48"):
            return False
    return True


def resolve_public(host, port):
    answers = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    unique = []
    for family, kind, protocol, _, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6) or not public_address(address[0]):
            raise PermissionError("non_public_upstream")
        item = (family, kind, protocol, address)
        if item not in unique:
            unique.append(item)
    if not unique:
        raise OSError("no_upstream_address")
    return unique


def connect_public(target):
    # DNS is resolved once and every answer is validated. connect() receives a
    # numerical sockaddr, so it cannot resolve again after validation.
    answers = resolve_public(target["host"], target["port"])
    deadline = time.monotonic() + 12
    for family, kind, protocol, address in answers:
        connection = socket.socket(family, kind, protocol)
        try:
            connection.settimeout(max(.1, min(4, deadline - time.monotonic())))
            connection.connect(address)
            connection.settimeout(5)
            return connection
        except OSError:
            connection.close()
            if time.monotonic() >= deadline:
                break
    raise OSError("upstream_unreachable")


def atomic_json(path, data):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("symlink_refused")
    previous = path.stat() if path.exists() else None
    fd, temp = tempfile.mkstemp(prefix=".relay-", dir=path.parent)
    try:
        os.chmod(temp, 0o600)
        if previous is not None and os.name != "nt" and os.geteuid() == 0:
            os.chown(temp, previous.st_uid, previous.st_gid)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, separators=(",", ":"), ensure_ascii=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()

    @contextlib.contextmanager
    def transaction(self):
        with self.lock:
            lock_path = self.path.with_suffix(".lock")
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(lock_path, flags, 0o600)
            try:
                if os.name != "nt":
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)

    def read(self):
        if self.path.is_symlink():
            raise ValueError("symlink_refused")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": 1, "accounts": {}}
        if data.get("version") != 1 or not isinstance(data.get("accounts"), dict):
            raise ValueError("invalid_account_store")
        return data

    def account(self, username):
        return self.read()["accounts"].get(username)

    def create(self, username, password=None, max_tunnels=64):
        if not USER.fullmatch(username) or not 1 <= max_tunnels <= 256:
            raise ValueError("invalid_account_options")
        password = password or secrets.token_urlsafe(36)
        if not 24 <= len(password) <= 256 or ":" in password:
            raise ValueError("invalid_password")
        salt = secrets.token_bytes(16)
        derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        with self.transaction():
            data = self.read()
            if username in data["accounts"]:
                raise ValueError("account_exists")
            data["accounts"][username] = {"enabled": True, "revision": secrets.token_hex(16), "maxTunnels": max_tunnels,
                                          "salt": salt.hex(), "passwordHash": derived.hex(), "upstream": None, "bindingRevision": 0}
            atomic_json(self.path, data)
        return password

    def disable(self, username):
        with self.transaction():
            data = self.read()
            if username not in data["accounts"]:
                raise ValueError("account_not_found")
            data["accounts"][username]["enabled"] = False
            data["accounts"][username]["revision"] = secrets.token_hex(16)
            atomic_json(self.path, data)

    def bind(self, username, revision, target, expected_revision=None):
        target = endpoint(target) if target is not None else None
        with self.transaction():
            data = self.read()
            account = data["accounts"].get(username)
            if not account or not account.get("enabled"):
                raise PermissionError("account_changed")
            if expected_revision is not None and expected_revision != account.get("bindingRevision", 0):
                raise RuntimeError("binding_revision_conflict")
            if account["revision"] != revision:
                raise PermissionError("account_changed")
            if account.get("upstream") != target:
                account["upstream"] = target
                account["revision"] = secrets.token_hex(16)
                account["bindingRevision"] = account.get("bindingRevision", 0) + 1
                atomic_json(self.path, data)
        return target, account.get("bindingRevision", 0)


class RelayServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, address, context, store, connector=connect_public, resolver=resolve_public, marker="", idle_timeout=300):
        self.context, self.store = context, store
        self.connector, self.resolver = connector, resolver
        self.marker, self.idle_timeout = marker, idle_timeout
        self.slots = threading.BoundedSemaphore(256)
        self.auth_slots = threading.BoundedSemaphore(4)
        self.guard = threading.RLock()
        self.active, self.auth_cache, self.failures = {}, {}, {}
        super().__init__(address, Handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            self.shutdown_request(request)

    def process_request_thread(self, request, address):
        wrapped = None
        try:
            wrapped = self.context.wrap_socket(request, server_side=True)
            wrapped.settimeout(10)
            super().process_request_thread(wrapped, address)
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.shutdown_request(wrapped or request)
            self.slots.release()

    def handle_error(self, request, address):
        # Never serialize request lines, headers, credentials or destinations.
        pass

    def authenticate(self, value, peer):
        try:
            if not value or len(value) > 512 or not value.startswith("Basic "):
                return None
            decoded = base64.b64decode(value[6:], validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
            if not USER.fullmatch(username) or not 24 <= len(password) <= 256:
                return None
            account = self.store.account(username)
            if not account or not account.get("enabled"):
                return None
            cache_key = hashlib.sha256(value.encode()).digest()
            now = time.monotonic()
            with self.guard:
                cached = self.auth_cache.get(cache_key)
                if cached and cached[0] == account["revision"] and cached[1] > now:
                    return username, account
                failure = self.failures.get(peer)
                if failure and failure[0] > now - 60 and failure[1] >= 15:
                    return None
            if not self.auth_slots.acquire(timeout=1):
                return None
            try:
                result = hashlib.scrypt(password.encode(), salt=bytes.fromhex(account["salt"]), n=16384, r=8, p=1, dklen=32)
            finally:
                self.auth_slots.release()
            if not hmac.compare_digest(result, bytes.fromhex(account["passwordHash"])):
                with self.guard:
                    if len(self.failures) > 2048:
                        self.failures.clear()
                    previous = self.failures.get(peer, (now, 0))
                    self.failures[peer] = (previous[0], previous[1] + 1) if previous[0] > now - 60 else (now, 1)
                return None
            with self.guard:
                if len(self.auth_cache) > 2048:
                    self.auth_cache.clear()
                self.auth_cache[cache_key] = (account["revision"], now + 30)
            return username, account
        except (ValueError, UnicodeError, KeyError, OSError):
            return None

    def reserve(self, username, revision, limit):
        with self.guard:
            current = self.store.account(username)
            if not current or not current.get("enabled") or current["revision"] != revision:
                return False
            if self.active.get(username, 0) >= limit:
                return False
            self.active[username] = self.active.get(username, 0) + 1
            return True

    def release(self, username):
        with self.guard:
            self.active[username] = max(0, self.active.get(username, 0) - 1)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "MCProxyRelay/1"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    rbufsize = 0  # CONNECT must not lose pipelined tunnel bytes in buffered headers.

    def log_message(self, *args):
        pass

    def reply(self, status, data, challenge=None):
        body = json.dumps(data, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        if challenge:
            self.send_header(challenge, 'Basic realm="MC Proxy relay", charset="UTF-8"')
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        self.reply(code, {"error": "invalid_request"})

    def auth(self, proxy=False):
        header = "Proxy-Authorization" if proxy else "Authorization"
        values = self.headers.get_all(header, [])
        result = self.server.authenticate(values[0] if len(values) == 1 else None, self.client_address[0])
        if not result:
            self.reply(407 if proxy else 401, {"error": "authentication_required"}, "Proxy-Authenticate" if proxy else "WWW-Authenticate")
        return result

    def do_GET(self):
        if self.path == "/healthz":
            return self.reply(200, {"service": "mc-proxy-relay", "version": 1, "status": "ok", "marker": self.server.marker})
        if self.path != "/v1/status":
            return self.reply(404, {"error": "not_found"})
        authenticated = self.auth()
        if authenticated:
            username, account = authenticated
            with self.server.guard:
                active = self.server.active.get(username, 0)
            self.reply(200, {"ok": True, "account": username, "enabled": True, "upstream": account.get("upstream"),
                             "activeTunnels": active, "maxTunnels": account["maxTunnels"], "bindingRevision": account.get("bindingRevision", 0)})

    def do_POST(self):
        if self.path != "/v1/upstream":
            return self.reply(404, {"error": "not_found"})
        authenticated = self.auth()
        if not authenticated:
            return
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            return self.reply(400, {"error": "invalid_body"})
        try:
            length = int(self.headers["Content-Length"])
            if not 1 <= length <= MAX_BODY:
                raise ValueError("invalid_length")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("invalid_content_type")
            chunks, remaining = [], length
            while remaining:
                chunk = self.rfile.read(remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) != length:
                raise ValueError("truncated_body")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("invalid_body")
            expected = data.pop("expectedRevision", None)
            if expected is not None and (isinstance(expected, bool) or not isinstance(expected, int) or expected < 0):
                raise ValueError("invalid_revision")
            if self.command == "DELETE":
                if data or expected is None:
                    raise ValueError("invalid_delete_body")
                target = None
            else:
                target = endpoint(data)
                self.server.resolver(target["host"], target["port"])
            with self.server.guard:
                current = self.server.store.account(authenticated[0])
                if current and current.get("upstream") != target and self.server.active.get(authenticated[0], 0):
                    return self.reply(409, {"error": "upstream_in_use"})
                target, revision = self.server.store.bind(authenticated[0], authenticated[1]["revision"], target, expected)
            self.reply(200, {"ok": True, "upstream": target, "bindingRevision": revision})
        except RuntimeError:
            self.reply(409, {"error": "binding_revision_conflict"})
        except PermissionError:
            self.reply(403, {"error": "upstream_forbidden_or_account_changed"})
        except (ValueError, UnicodeError):
            self.reply(400, {"error": "invalid_upstream"})
        except OSError:
            self.reply(502, {"error": "upstream_resolution_failed"})

    do_PUT = do_POST
    do_DELETE = do_POST

    def do_CONNECT(self):
        authenticated = self.auth(proxy=True)
        if not authenticated:
            return
        username, account = authenticated
        try:
            target = authority(self.path)
        except ValueError:
            return self.reply(400, {"error": "invalid_authority"})
        if target != account.get("upstream"):
            return self.reply(403, {"error": "upstream_not_registered"})
        if not self.server.reserve(username, account["revision"], account["maxTunnels"]):
            return self.reply(429, {"error": "tunnel_limit_or_account_changed"})
        upstream = None
        try:
            upstream = self.server.connector(target)
            current = self.server.store.account(username)
            if not current or not current.get("enabled") or current["revision"] != account["revision"]:
                return self.reply(403, {"error": "account_changed"})
            self.send_response(200, "Connection established")
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True
            self.connection.settimeout(5)
            upstream.settimeout(5)
            last_data, last_check = time.monotonic(), 0
            while time.monotonic() - last_data < self.server.idle_timeout:
                now = time.monotonic()
                if now - last_check >= 1:
                    current = self.server.store.account(username)
                    if not current or not current.get("enabled") or current["revision"] != account["revision"]:
                        break
                    last_check = now
                readable = [self.connection] if self.connection.pending() else select.select([self.connection, upstream], [], [], 1)[0]
                if not readable:
                    continue
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = upstream if source is self.connection else self.connection
                    destination.sendall(data)
                    last_data = time.monotonic()
        except PermissionError:
            if upstream is None:
                self.reply(403, {"error": "non_public_upstream"})
        except (OSError, ValueError, KeyError):
            if upstream is None:
                self.reply(502, {"error": "upstream_unreachable"})
        finally:
            self.close_connection = True
            if upstream:
                upstream.close()
            self.server.release(username)

    def do_HEAD(self):
        self.reply(405, {"error": "method_not_allowed"})

    do_PATCH = do_OPTIONS = do_HEAD


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default="/var/lib/mc-proxy-relay/accounts.json")
    parser.add_argument("--cert", default="/etc/proxypilot-relay-health/server-cert.pem")
    parser.add_argument("--key", default="/etc/proxypilot-relay-health/server-key.pem")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.set_alpn_protocols(["http/1.1"])
    marker_path = Path("/etc/proxypilot-relay-health/nonce")
    marker = marker_path.read_text(encoding="ascii").strip() if marker_path.is_file() else ""
    store = Store(args.state)
    store.read()  # Fail before binding on a malformed existing store.
    with RelayServer((args.listen, args.port), context, store, marker=marker) as server:
        server.serve_forever(poll_interval=.5)


if __name__ == "__main__":
    main()
