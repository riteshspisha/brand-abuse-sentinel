"""Page-opened sockets on the controlled lab (U19, R39, R41; markers lab, docker,
security).

A page's WebSockets and WebRTC are not HTTP requests, so the browser's method
gate does not see them, and a tunnel through the proxy would carry them. A
WebSocket server runs beside lab-web, in its network namespace on port 443, so
lab hostnames on 443 reach it through the lab sandbox proxy. Two layers keep it
unreached:

- the proxy, without the browser: no tunnel to port 80, and a tunnel that
  does not start like a TLS ClientHello (a prefix check) is closed before a byte
  reaches the server;
- the browser worker: every WebSocket is answered inside the browser and
  recorded, and WebRTC and workers are removed from every frame.

Positive controls show the server answers a WebSocket when reached directly, and
that a TLS tunnel through the same proxy does reach it. Needs the sandbox image.
"""

import asyncio
import json
import time

import pytest
from tests.docker_support import (
    LAB_SANDBOX_NET,
    REPO,
    compose,
    labelled,
    make_runner,
    net_settings,
    probe,
    runtime_or_skip,
    wait_running,
)

from brandsentinel.config import BrowserSettings, load_config
from brandsentinel.sandbox.browser_client import BrowserClient

pytestmark = [pytest.mark.lab, pytest.mark.docker, pytest.mark.security]

HOST = "go-luminafoundation.test"
LISTENER = "bs-lab-socket-listener"
SOURCE = REPO / "tests" / "lab" / "socket_listener.py"
HANDSHAKE = (
    f"GET /socket?via=probe HTTP/1.1\r\nHost: {HOST}:443\r\nUpgrade: websocket\r\n"
    "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n"
).encode()
MESSAGE = b"lumina-socket-message probe"
MASKED = bytes([0x81, 0x80 | len(MESSAGE), 0, 0, 0, 0]) + MESSAGE  # a zero mask
DIRECT = f"""
import socket
s = socket.create_connection(("127.0.0.1", 443), timeout=5)
s.sendall({HANDSHAKE!r} + {MASKED!r})
print(s.recv(4096)[:32])
"""


@pytest.fixture(scope="module")
def docker():
    d = runtime_or_skip()
    compose(d, "lab.compose.yaml", "up", "-d")
    for name in ("bs-lab-web", LAB_SANDBOX_NET.proxy_container):
        wait_running(d, name)
    yield d
    assert labelled(d) == []


@pytest.fixture(scope="module")
def listener(docker):
    docker.call_sync("rm", "--force", LISTENER)
    started = docker.call_sync(
        "run", "--detach", "--name", LISTENER,
        "--network", "container:bs-lab-web",  # lab-web's address, its free port 443
        "--user", "pwuser", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "32", "--memory", "64m",
        "--volume", f"{SOURCE}:/srv/socket_listener.py:ro",
        "--entrypoint", "python3", "brandsentinel-sandbox:local",
        "/srv/socket_listener.py", "443",
    )  # fmt: skip
    assert started.ok, started.stderr
    try:
        deadline = time.monotonic() + 30
        while "listening" not in docker.call_sync("logs", LISTENER).stdout:
            assert time.monotonic() < deadline, "socket listener did not start"
            time.sleep(0.5)
        yield lambda: connections(docker)
    finally:
        docker.call_sync("rm", "--force", LISTENER)


def connections(docker) -> list[dict]:
    out = docker.call_sync("logs", LISTENER).stdout
    records = [json.loads(x) for x in out.splitlines() if x.startswith("{")]
    return [r for r in records if "listening" not in r]


def settled(docker, before: int) -> list[dict]:
    """Connections after the first `before`, once the listener has logged them all."""
    time.sleep(2)  # a connection is logged when it ends
    return connections(docker)[before:]


def proxy_records(docker, since: str) -> list[dict]:
    logs = docker.call_sync("logs", "--since", since, LAB_SANDBOX_NET.proxy_container)
    return [json.loads(x) for x in logs.stderr.splitlines() if x.startswith("{")]


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1))


def test_positive_control_the_listener_answers_a_websocket_reached_directly(docker, listener):
    before = len(listener())
    r = docker.call_sync("exec", LISTENER, "python3", "-c", DIRECT)
    assert r.ok and "101 Switching" in r.stdout, (r.stdout, r.stderr)
    (seen,) = settled(docker, before)
    assert seen["upgrade"] and seen["messages"] == [MESSAGE.decode()]


def test_the_proxy_tunnels_only_tls_to_port_443_whatever_the_browser_does(docker, listener):
    before, since = len(listener()), now()
    via = {"kind": "tunnel", "proxy_host": LAB_SANDBOX_NET.proxy_ip, "proxy_port": 3128}
    results = probe(
        make_runner(docker, net=LAB_SANDBOX_NET),
        LAB_SANDBOX_NET.name,
        [
            {"id": "ws 80", "authority": f"{HOST}:80", "payload_hex": (HANDSHAKE + MASKED).hex(),
             **via},
            {"id": "ws 443", "authority": f"{HOST}:443", "payload_hex": (HANDSHAKE + MASKED).hex(),
             **via},
            {"id": "turn 443", "authority": f"{HOST}:443",
             "payload_hex": "000300082112a442" + "00" * 12, **via},  # a TURN Allocate
            {"id": "tls 443", "authority": f"{HOST}:443", "client_hello": HOST, **via},
        ],
    )  # fmt: skip
    assert results["ws 80"] == "status:403", results
    assert results["ws 443"] == "status:200 closed" and results["turn 443"] == "status:200 closed"
    seen = settled(docker, before)
    # The plain tunnels reached the listener as connections that carried nothing;
    # the TLS one (the positive control) carried its ClientHello.
    assert all(s["request"] is None and s["messages"] == [] for s in seen), seen
    carried = [s["raw"] for s in seen if s["raw"]]
    assert len(carried) == 1 and carried[0].startswith("160301"), seen
    decisions = {
        (r["port"], r["reason"]) for r in proxy_records(docker, since) if r.get("host") == HOST
    }
    assert {(80, "port_not_allowed"), (443, "tunnel_not_tls"), (443, "connect")} <= decisions


def test_page_websockets_webrtc_and_workers_never_reach_the_destination(docker, listener):
    before, since = len(listener()), now()
    hosts = frozenset(load_config(REPO / "config" / "lab.yaml").net.lab.hosts)
    c = BrowserClient(
        make_runner(docker, net=LAB_SANDBOX_NET),
        BrowserSettings(),
        net_settings(LAB_SANDBOX_NET),
        lab_hosts=hosts,
    )
    r = asyncio.run(c.render(f"http://{HOST}/socket.html", job="b-sockets"))
    assert r.status == "ok", (r.reason, r.runs)
    assert settled(docker, before) == []  # not even a connection
    sockets = [a["url"].split("via=")[1] for a in r.doc["attempts"]["websockets"]]
    assert sorted(sockets) == ["frame", "ws443", "ws80", "wss"]
    assert r.doc["attempt_counts"]["websockets"] == 4
    text = r.doc["text"]
    assert "worker: refused" in text and "webrtc: refused" in text and "reply" not in text
    blocked = {a["url"].split("via=")[1] for a in r.doc["attempts"]["blocked_requests"]}
    assert blocked == {"beacon", "keepalive"}
    sent = [x for x in proxy_records(docker, since) if x.get("method")]
    assert {x["method"] for x in sent} == {"GET"}, sent  # no tunnel was even asked for
