# A page's WebSockets and WebRTC bypassed the browser's GET-only gate

**Context.** The browser worker stopped every request other than GET or HEAD
with `context.route("**/*", gate)`, and the egress proxy forwarded plain HTTP
only as GET or HEAD. It accepted `CONNECT` tunnels to ports 80 and 443 without
looking inside them (KTD10).

**Problem.** A PR review asked whether a page could still open a WebSocket. A
lab page (`labsites/redirects/socket.html`) tried, with a WebSocket server
beside lab-web on port 443. On the M7 worker:

- `ws://host/` went through `CONNECT host:80`.
- `ws://host:443/`, from the page and from a dedicated Worker, connected
  through `CONNECT host:443`. Its message reached the server and the reply
  came back.
- `wss://` and WebRTC (`turn:`/`turns:` over TCP, with `iceTransportPolicy:
  relay`) sent TLS ClientHellos and TURN Allocate requests through the proxy.
  `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` still allows
  TURN over a proxied TCP connection.
- None of it appeared in the render's network log: `context.route` and the
  request events cover HTTP only.

What did not help:

- **CDP `Network.setBlockedURLs` with `ws://*` and `wss://*`.** WebSockets
  still connected.
- **`--disable-blink-features=RTCPeerConnection`.** `RTCPeerConnection` was
  still a function.
- **Playwright's `route_web_socket`.** It does handle page and iframe sockets,
  but it does not see a dedicated Worker's sockets.
- **Calling `WebSocketRoute.close()` from the handler.** With the sync API it
  deadlocked the render until the wall-time kill.

**Fix.**

1. **The proxy, independent of the browser.** It tunnels only to port 443, and
   a tunnel must open with a TLS ClientHello record (type 22, version 3.x,
   handshake type 1), checked on its first six bytes. Otherwise it is closed
   before a byte is relayed, and logged as `tunnel_not_tls`. Plain HTTP never
   needs a tunnel: it is forwarded, GET and HEAD only. This stops `ws://` on any
   port, plain TURN, and any other plaintext protocol Chromium would tunnel
   through `CONNECT`. It is a prefix filter, not TLS enforcement: a raw-socket
   client can forge the six bytes and send plaintext after them (accepted, see
   Limits).
2. **The worker, as defense in depth.** It handles every WebSocket with
   `route_web_socket` without calling `connect_to_server` or `close`, and
   records its URL as a `websockets` page action. An init script deletes
   `RTCPeerConnection` (and its relatives), `Worker` and `SharedWorker` in
   every frame before page scripts run.

Regression: `tests/lab/test_browser_sockets.py`.

- The proxy test sends a raw WebSocket handshake, a TURN Allocate and a real
  ClientHello from a sandbox container. Its positive controls show the server
  answers a WebSocket reached directly, and the TLS tunnel does reach the
  server.
- The browser test renders the page and requires that nothing reaches the
  server.
- Both fail on the M7 image.
- `tests/security/test_proxy.py` covers the tunnel policy in process.

**Limits (not claimed).** The tunnel check stops Chromium's plaintext protocols,
not a client that controls its own bytes: code with raw socket access can forge
the prefix (pinned by `test_the_tls_check_is_a_prefix_filter_...`), and could as
well use real TLS to its own server. What a tunnel to port 443 carries is opaque, so
`wss://` and `turns:` are stopped only by the browser-side layer. Page scripts
can still send GET requests, carrying whatever they put in the URL, to any
destination the proxy allows. BrandSentinel does not interact with the page;
the page is not prevented from every remote side effect.

**Lesson.** "Only GET leaves the browser" holds only for the protocols the gate
sees. Enumerate every protocol a page can open (HTTP, WebSocket, WebRTC,
WebTransport, workers), test each against a real server, and enforce what can
be enforced at the proxy, where the browser cannot undo it.
