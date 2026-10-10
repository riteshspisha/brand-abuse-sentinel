"""Network probe run inside sandbox containers by the Docker test suites.

Standard library only. Reads a JSON list of checks on stdin and prints one JSON
object mapping each check's `id` to its result. Every network attempt has a
short timeout. Result values:

- tcp:         "connected" or the error class name
- udp:         "answered" (any reply arrived) or "no_reply" / error class
- resolve:     "resolved:<addresses>" or the error class name
- http:        "status:<code>" (a direct or proxied HTTP request) or error
- connect:     "status:<code>" for a CONNECT through a proxy, or error
- read/write/exec/proc: filesystem and process facts for isolation checks
"""

import json
import os
import socket
import struct
import subprocess
import sys

TIMEOUT = 3.0


def tcp(host, port, family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((host, port))
        return "connected"
    except OSError as e:
        return type(e).__name__
    finally:
        s.close()


def udp(host, port, payload_hex, family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.sendto(bytes.fromhex(payload_hex), (host, port))
        s.recvfrom(2048)
        return "answered"
    except TimeoutError:
        return "no_reply"
    except OSError as e:
        return type(e).__name__
    finally:
        s.close()


def stun_request():
    # RFC 5389 binding request: type 0x0001, length 0, magic cookie, transaction id.
    return (struct.pack("!HHI", 1, 0, 0x2112A442) + os.urandom(12)).hex()


def dns_query(name):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return (header + qname + struct.pack("!HH", 1, 1)).hex()


def resolve(name):
    try:
        infos = socket.getaddrinfo(name, 80, proto=socket.IPPROTO_TCP)
        return "resolved:" + ",".join(sorted({i[4][0] for i in infos}))
    except OSError as e:
        return type(e).__name__


def _status(sock):
    data = b""
    while b"\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    parts = data.split(b" ", 2)
    return f"status:{int(parts[1])}" if len(parts) > 1 and parts[1].isdigit() else "no_status"


def http(host, port, target, host_header, user_agent=None, method="GET"):
    try:
        s = socket.create_connection((host, port), timeout=TIMEOUT)
    except OSError as e:
        return type(e).__name__
    try:
        ua = f"User-Agent: {user_agent}\r\n" if user_agent else ""
        head = f"{method} {target} HTTP/1.1\r\nHost: {host_header}\r\n{ua}"
        s.sendall((head + "Connection: close\r\n\r\n").encode())
        return _status(s)
    except OSError as e:
        return type(e).__name__
    finally:
        s.close()


def body(host, port, target, host_header, user_agent):
    try:
        s = socket.create_connection((host, port), timeout=TIMEOUT)
    except OSError as e:
        return type(e).__name__
    try:
        s.sendall(
            f"GET {target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        data = b""
        while len(data) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace")
    except OSError as e:
        return type(e).__name__
    finally:
        s.close()


def connect(proxy_host, proxy_port, authority):
    try:
        s = socket.create_connection((proxy_host, proxy_port), timeout=TIMEOUT * 3)
    except OSError as e:
        return type(e).__name__
    try:
        s.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        return _status(s)
    except OSError as e:
        return type(e).__name__
    finally:
        s.close()


def facts():
    status = {}
    with open("/proc/self/status") as f:
        for line in f:
            k, _, v = line.partition(":")
            status[k] = v.strip()
    try:
        with open("/probe-write-test", "w") as f:
            f.write("x")
        root_writable = True
    except OSError:
        root_writable = False
    exec_ok = False
    try:
        path = "/tmp/probe-exec.sh"
        with open(path, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o700)
        exec_ok = subprocess.run([path], check=False).returncode == 0  # noqa: S603
    except OSError:
        pass
    return {
        "uid": os.getuid(),
        "cap_eff": status.get("CapEff"),
        "cap_bnd": status.get("CapBnd"),
        "no_new_privs": status.get("NoNewPrivs"),
        "seccomp": status.get("Seccomp"),
        "root_writable": root_writable,
        "tmp_exec": exec_ok,
        "interfaces": sorted(os.listdir("/sys/class/net")),
        "docker_sock": any(os.path.exists(p) for p in ("/var/run/docker.sock", "/run/docker.sock")),
    }


def run(check):
    kind = check["kind"]
    if kind == "tcp":
        fam = socket.AF_INET6 if ":" in check["host"] else socket.AF_INET
        return tcp(check["host"], check["port"], fam)
    if kind == "udp_stun":
        return udp(check["host"], check["port"], stun_request())
    if kind == "udp_dns":
        return udp(check["host"], 53, dns_query(check.get("name", "example.com")))
    if kind == "resolve":
        return resolve(check["name"])
    if kind == "http":
        return http(
            check["host"],
            check["port"],
            check["target"],
            check["host_header"],
            check.get("user_agent"),
            check.get("method", "GET"),
        )
    if kind == "body":
        return body(
            check["host"],
            check["port"],
            check["target"],
            check["host_header"],
            check["user_agent"],
        )
    if kind == "connect":
        return connect(check["proxy_host"], check["proxy_port"], check["authority"])
    if kind == "facts":
        return facts()
    return f"unknown kind {kind}"


def main():
    checks = json.loads(sys.stdin.read() or "[]")
    print(json.dumps({c["id"]: run(c) for c in checks}))


if __name__ == "__main__":
    main()
