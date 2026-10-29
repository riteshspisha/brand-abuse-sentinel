"""A WebSocket server for the lab socket test (stdlib only; runs in a container).

Started beside lab-web in its network namespace, so lab hostnames on port 443
reach it through the lab sandbox proxy (lab-web itself listens only on 80). It
completes the WebSocket handshake, reads one message and answers it, and prints
one JSON line per connection: the request line, whether it was an upgrade, the
messages received, or the first bytes of anything that is not HTTP (TLS, TURN).
"""

import base64
import hashlib
import json
import socket
import sys
import threading

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Reader:
    """Exact reads from a socket, starting with bytes already received."""

    def __init__(self, conn: socket.socket, buffered: bytes) -> None:
        self.conn, self.buf = conn, buffered

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.conn.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def frame(r: Reader) -> bytes | None:
    head = r.read(2)
    if len(head) < 2:
        return None
    length = head[1] & 0x7F
    if length == 126:
        length = int.from_bytes(r.read(2), "big")
    elif length == 127:
        length = int.from_bytes(r.read(8), "big")
    mask = r.read(4) if head[1] & 0x80 else b"\0\0\0\0"
    data = r.read(min(length, 4096))
    return bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def serve(conn: socket.socket) -> None:
    seen: dict = {"request": None, "upgrade": False, "messages": [], "raw": None}
    try:
        conn.settimeout(10)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 16384:
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw += chunk
        if not raw.startswith((b"GET ", b"HEAD ")):
            seen["raw"] = raw[:16].hex()
            return
        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        seen["request"] = lines[0]
        fields = (h.partition(":") for h in lines[1:])
        headers = {k.strip().lower(): v.strip() for k, _, v in fields}
        if headers.get("upgrade", "").lower() != "websocket":
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            return
        seen["upgrade"] = True
        key = headers.get("sec-websocket-key", "").encode()
        accept = base64.b64encode(hashlib.sha1(key + GUID).digest())  # noqa: S324 - RFC 6455
        conn.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        reader = Reader(conn, rest)
        message = frame(reader)
        if message is not None:
            seen["messages"].append(message.decode("utf-8", "replace"))
            reply = b"lumina-socket-reply"
            conn.sendall(bytes([0x81, len(reply)]) + reply)
            frame(reader)  # the close, or nothing
    except OSError as e:
        seen["error"] = type(e).__name__
    finally:
        print(json.dumps(seen), flush=True)
        conn.close()


def main() -> None:
    server = socket.create_server(("0.0.0.0", int(sys.argv[1])))  # noqa: S104 - lab only
    print(json.dumps({"listening": int(sys.argv[1])}), flush=True)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
