#!/usr/bin/env python3
"""infrlo VLESS-over-WS -- original minimal implementation (stdlib only).

Design goals:
- infrlo only exposes an HTTP/WS entry point, no raw TCP port, so REALITY
  is not possible here. By protocol priority, the best achievable tier on
  this platform is VLESS + WS + TLS (TLS is terminated by the infrlo edge;
  this service only speaks plain WS internally).
- Nothing copied from any existing repo. VLESS header layout is parsed
  from the public protocol spec by hand; WebSocket handshake and frame
  codec are implemented by hand on top of the raw socket.
- All runtime parameters come from environment variables. No secret,
  domain, or third-party default is baked into the code.

Environment variables (set in the infrlo console at deploy time):
    UUID         Required. VLESS auth UUID. No default; missing or
                 malformed value makes the process exit at startup.
    NAME         Node name, default "heisi". Only used for the # remark
                 in the subscription link.
    SUB_PATH     Subscription path, default "sub". GET /<SUB_PATH> returns
                 the subscription content.
    WS_PATH      VLESS WebSocket path, default "/vless". The client's
                 path must match.
    PORT         Listen port, default 8080. infrlo injects the real port.
    PROJECT_URL  Deploy domain without "https://", e.g.
                 heisi.example.infrlo.com. Used to build the subscription
                 link. Empty means "not configured": the subscription
                 page only says so, it never invents a domain.

Behaviour:
    GET /               Disguise page (static HTML, proxy-unrelated).
    GET /<SUB_PATH>    One plain-text VLESS link (not base64).
    WS  <WS_PATH>      VLESS-over-WS. TCP only (command 1). UDP / MUX
                       connections are closed immediately.
"""

import base64
import hashlib
import os
import re
import socket
import struct
import sys
import threading
import uuid as uuid_mod

# ---------------------------------------------------------------- config

def read_env(name, fallback):
    value = os.environ.get(name)
    if value is None or str(value).strip() == "":
        return fallback
    return str(value).strip()


PORT = read_env("PORT", "8080")
UUID_TEXT = read_env("UUID", "")
NAME = read_env("NAME", "heisi")
SUB_PATH = read_env("SUB_PATH", "sub").lstrip("/")
WS_PATH = read_env("WS_PATH", "/vless")
if not WS_PATH.startswith("/"):
    WS_PATH = "/" + WS_PATH
PROJECT_URL = read_env("PROJECT_URL", "")
if PROJECT_URL.startswith("https://"):
    PROJECT_URL = PROJECT_URL[len("https://"):]
if PROJECT_URL.startswith("http://"):
    PROJECT_URL = PROJECT_URL[len("http://"):]
PROJECT_URL = PROJECT_URL.rstrip("/")

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
if not UUID_RE.match(UUID_TEXT):
    print(
        "[fatal] UUID missing or malformed. "
        "Set env UUID to a valid UUID before starting.",
        file=sys.stderr,
        flush=True,
    )
    sys.exit(1)
try:
    PORT_INT = int(PORT)
except ValueError:
    print("[fatal] PORT invalid.", file=sys.stderr, flush=True)
    sys.exit(1)
if not 1 <= PORT_INT <= 65535:
    print("[fatal] PORT invalid.", file=sys.stderr, flush=True)
    sys.exit(1)

EXPECTED_UUID = uuid_mod.UUID(UUID_TEXT).bytes
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# ---------------------------------------------------------------- helpers

def log(message):
    print(message, flush=True)


def read_exact(sock, count):
    """Read exactly `count` bytes, or return fewer on EOF/error."""
    chunks = []
    remaining = count
    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_http_headers(sock):
    """Read one HTTP request header block, byte by byte (no over-read)."""
    data = bytearray()
    while len(data) < 65536:
        try:
            byte = sock.recv(1)
        except OSError:
            return None
        if not byte:
            return None
        data += byte
        if data.endswith(b"\r\n\r\n"):
            return bytes(data)
    return None


def parse_http_request(raw):
    text = raw.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    if not lines:
        return None, None, {}
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None, None, {}
    method = parts[0].upper()
    path = parts[1].split("?", 1)[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return method, path, headers


def send_http(sock, status, content_type, body):
    if isinstance(body, str):
        body = body.encode("utf-8")
    head = (
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n" % (status, content_type, len(body))
    )
    try:
        sock.sendall(head.encode("iso-8859-1") + body)
    except OSError:
        pass


def build_vless_link():
    if not PROJECT_URL:
        return None
    # path is URL-encoded so the client sends exactly WS_PATH.
    from urllib.parse import quote

    encoded_path = quote(WS_PATH, safe="")
    link = (
        "vless://%s@%s:443?encryption=none&security=tls"
        "&sni=%s&type=ws&host=%s&path=%s#%s"
        % (UUID_TEXT, PROJECT_URL, PROJECT_URL, PROJECT_URL, encoded_path, NAME)
    )
    return link


DISGUISE_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Service</title></head>
<body><h1>Service is running.</h1>
<p>Nothing to see here.</p></body></html>
"""

# ------------------------------------------------------- websocket codec

def ws_accept_key(client_key):
    digest = hashlib.sha1((client_key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def send_ws_frame(sock, opcode, payload):
    """Send one server frame (never masked, FIN set)."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.append(126)
        header += struct.pack("!H", length)
    else:
        header.append(127)
        header += struct.pack("!Q", length)
    sock.sendall(bytes(header) + payload)


def read_ws_frame(sock):
    """Read one client frame. Returns (opcode, payload) or (None, None)."""
    head = read_exact(sock, 2)
    if len(head) < 2:
        return None, None
    first, second = head[0], head[1]
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        ext = read_exact(sock, 2)
        if len(ext) < 2:
            return None, None
        length = struct.unpack("!H", ext)[0]
    elif length == 127:
        ext = read_exact(sock, 8)
        if len(ext) < 8:
            return None, None
        length = struct.unpack("!Q", ext)[0]
    mask_key = b""
    if masked:
        mask_key = read_exact(sock, 4)
        if len(mask_key) < 4:
            return None, None
    payload = read_exact(sock, length) if length > 0 else b""
    if len(payload) < length:
        return None, None
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return opcode, payload


# ------------------------------------------------------------ vless core

def parse_vless_header(buf):
    """Parse a VLESS header from the head of `buf`.

    Returns (version, command, host, port, header_len) or None when the
    buffer does not yet hold a complete header.
    Layout: version(1) + uuid(16) + addon_len(1) + addon + command(1)
    + port(2) + addr_type(1) + addr + (no trailing bytes in header).
    """
    if len(buf) < 1 + 16 + 1:
        return None
    version = buf[0]
    client_uuid = bytes(buf[1:17])
    if client_uuid != EXPECTED_UUID:
        return "BAD_UUID"
    addon_len = buf[17]
    offset = 18 + addon_len
    if len(buf) < offset + 1 + 2 + 1:
        return None
    command = buf[offset]
    port = struct.unpack("!H", bytes(buf[offset + 1 : offset + 3]))[0]
    addr_type = buf[offset + 3]
    pos = offset + 4
    if addr_type == 1:  # IPv4
        if len(buf) < pos + 4:
            return None
        host = socket.inet_ntoa(bytes(buf[pos : pos + 4]))
        header_len = pos + 4
    elif addr_type == 2:  # domain
        if len(buf) < pos + 1:
            return None
        domain_len = buf[pos]
        if len(buf) < pos + 1 + domain_len:
            return None
        host = bytes(buf[pos + 1 : pos + 1 + domain_len]).decode(
            "utf-8", errors="replace"
        )
        header_len = pos + 1 + domain_len
    elif addr_type == 3:  # IPv6
        if len(buf) < pos + 16:
            return None
        host = socket.inet_ntop(
            socket.AF_INET6, bytes(buf[pos : pos + 16])
        )
        header_len = pos + 16
    else:
        return "BAD_ADDR"
    return (version, command, host, port, header_len)


def forward_remote_to_ws(client_sock, remote_sock, stop):
    """Copy remote -> client as WS binary frames until EOF or stop."""
    try:
        while not stop.is_set():
            try:
                data = remote_sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            try:
                send_ws_frame(client_sock, 0x2, data)
            except OSError:
                break
    finally:
        stop.set()
        try:
            send_ws_frame(client_sock, 0x8, b"")
        except OSError:
            pass
        try:
            remote_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            client_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def handle_vless_ws(client_sock):
    """Run one VLESS-over-WS session on an already-upgraded socket."""
    buffer = bytearray()
    remote = None
    stop = threading.Event()
    forwarder = None
    try:
        while not stop.is_set():
            opcode, payload = read_ws_frame(client_sock)
            if opcode is None:
                break
            if opcode == 0x8:  # Close
                break
            if opcode == 0x9:  # Ping -> Pong
                try:
                    send_ws_frame(client_sock, 0xA, payload)
                except OSError:
                    break
                continue
            if opcode not in (0x0, 0x1, 0x2):
                continue
            if remote is None:
                buffer += payload
                parsed = parse_vless_header(buffer)
                if parsed is None:
                    # Header incomplete; wait for more frames.
                    if len(buffer) > 65536:
                        break
                    continue
                if parsed in ("BAD_UUID", "BAD_ADDR"):
                    break
                version, command, host, port, header_len = parsed
                if command != 1:  # Only TCP is supported.
                    break
                try:
                    remote = socket.create_connection((host, port), timeout=15)
                except OSError:
                    break
                # VLESS response header, then any first payload bytes.
                try:
                    send_ws_frame(client_sock, 0x2, bytes([version, 0]))
                except OSError:
                    break
                first = bytes(buffer[header_len:])
                buffer = bytearray()
                if first:
                    try:
                        remote.sendall(first)
                    except OSError:
                        break
                forwarder = threading.Thread(
                    target=forward_remote_to_ws,
                    args=(client_sock, remote, stop),
                    daemon=True,
                )
                forwarder.start()
            else:
                try:
                    remote.sendall(payload)
                except OSError:
                    break
    finally:
        stop.set()
        if remote is not None:
            try:
                remote.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                remote.close()
            except OSError:
                pass


def handle_connection(client_sock):
    try:
        raw = read_http_headers(client_sock)
        if raw is None:
            return
        method, path, headers = parse_http_request(raw)
        if method is None:
            return
        upgrade = headers.get("upgrade", "").lower()
        connection = headers.get("connection", "").lower()
        ws_key = headers.get("sec-websocket-key", "")
        if (
            path == WS_PATH
            and upgrade == "websocket"
            and "upgrade" in connection
            and ws_key
        ):
            accept = ws_accept_key(ws_key)
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n"
                "\r\n" % accept
            )
            client_sock.sendall(response.encode("ascii"))
            handle_vless_ws(client_sock)
            return
        if method != "GET":
            send_http(client_sock, "405 Method Not Allowed", "text/plain", "405")
            return
        if path == "/":
            send_http(client_sock, "200 OK", "text/html; charset=utf-8", DISGUISE_HTML)
            return
        if path == "/" + SUB_PATH:
            link = build_vless_link()
            if link is None:
                send_http(
                    client_sock,
                    "200 OK",
                    "text/plain; charset=utf-8",
                    "PROJECT_URL not configured.\n",
                )
            else:
                send_http(client_sock, "200 OK", "text/plain; charset=utf-8", link + "\n")
            return
        send_http(client_sock, "404 Not Found", "text/plain", "404")
    except OSError:
        pass
    finally:
        try:
            client_sock.close()
        except OSError:
            pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT_INT))
    server.listen(128)
    log("server is running on %d" % PORT_INT)
    while True:
        try:
            client, _addr = server.accept()
        except OSError:
            continue
        thread = threading.Thread(
            target=handle_connection, args=(client,), daemon=True
        )
        thread.start()


if __name__ == "__main__":
    main()
