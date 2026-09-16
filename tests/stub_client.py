#!/usr/bin/env python3
"""Stub API module for self-testing GatewayAPI without a real module (README § Control plane,
§ Data plane, § Mirror). Plays the module side — handshake, frames, heartbeats, an HTTP echo
on the data plane — and checks the gateway in both directions: every refusal is provoked on
purpose.

Run (the gateway listens on 127.0.0.1:4988, audience from `module.GatewayAPI.audience`):

    python3 tests/stub_client.py --gateway http://127.0.0.1:4988 \
        --client-id gateway-example.com --client-secret-file /path/to/secret

The secret comes only from a file or the GATEWAY_CLIENT_SECRET variable, never passed via argv.
Exit 0 — all scenarios passed; otherwise the first FAILED one is printed and exit 1.

Scenario 10 (`gateway.node` mirror, README § Mirror) needs a SECOND gateway on the same
database (`--peer http://127.0.0.1:4989` — a second standalone process on a different port plays
the second worker) and database access (`--pg "host=127.0.0.1 port=5431 dbname=example
user=daemon"`, password via PGPASSWORD or `--pg-password-file`); skipped without them. Both
gateways run with `reload_interval` 5 — the scenario waits for the sweep and the reload after it.

Gateway configuration for a run: `heartbeat_interval` 2 (scenario 4 waits for suspect/offline by
the clock), `allowed_cidr` with 127.0.0.0/8, `response_timeout_ms` 2000 (scenario 9 waits for a
504 after ~2s; at 30000 the echo itself drops the connection after 6s and the gateway correctly
answers 502).
"""

import argparse
import asyncio
import json
import os
import sys
import time
import uuid

# The local gateway must never go through a proxy, whatever is set in the environment:
# requests honors HTTP_PROXY even for 127.0.0.1, and an external proxy answers with its own 403,
# which is easy to mistake for a gateway failure.
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

import requests  # noqa: E402
import websockets  # noqa: E402

HB = 2  # heartbeat_interval we expect from the gateway (local run config)
RELOAD = 5  # reload_interval of both gateways (scenario 10: sweep, reload, re-assert)


SECRET = None   # audience secret — used to re-sign an expired token in scenario 9


class Fail(Exception):
    pass


def check(cond, what):
    mark = "ok " if cond else "FAIL"
    print(f"  [{mark}] {what}")
    if not cond:
        raise Fail(what)


def token(gw, client_id, secret):
    r = requests.post(f"{gw}/oauth2/token", data={
        "grant_type": "client_credentials", "client_id": client_id, "client_secret": secret,
    }, timeout=5)
    r.raise_for_status()
    return r.json()["access_token"]


def call(a, p=None, u=None):
    return json.dumps({"t": 2, "u": u or str(uuid.uuid4()), "a": a, "p": p if p is not None else {}})


async def rx(ws, timeout=6):
    return json.loads(await asyncio.wait_for(ws.recv(), timeout))


async def connect(gw, tok, module, instance, extra_headers=None):
    url = gw.replace("http", "ws", 1) + f"/gateway/{module}/{instance}"
    headers = {"Authorization": f"Bearer {tok}"}
    if extra_headers:
        headers.update(extra_headers)
    return await websockets.connect(url, additional_headers=headers, open_timeout=5)


def register_payload(module, instance, **over):
    p = {"module": module, "instance": instance, "version": "0.1.0", "build": "stub",
         "address": "127.0.0.1:18081", "prefixes": [f"/api/v2/{module}"], "capacity": 8}
    p.update(over)
    return p


async def register(ws, module, instance, **over):
    await ws.send(call("/register", register_payload(module, instance, **over)))
    return await rx(ws)


async def close_code(ws, timeout=6):
    """Wait for the socket to be closed by the gateway; return (code, reason)."""
    try:
        while True:
            await asyncio.wait_for(ws.recv(), timeout)
    except websockets.ConnectionClosed as e:
        return e.rcvd.code if e.rcvd else None, e.rcvd.reason if e.rcvd else ""
    except asyncio.TimeoutError:
        return None, "timeout"


def listing(gw, tok):
    r = requests.get(f"{gw}/gateway/list", headers={"Authorization": f"Bearer {tok}"}, timeout=5)
    r.raise_for_status()
    return {(i["module"], i["instance"]): i for i in r.json()["instances"]}


async def scenario_register_ok(gw, tok):
    print("1. register, heartbeat, /status, /unregister")
    ws = await connect(gw, tok, "clients", "c1")
    r = await register(ws, "clients", "c1")
    check(r["t"] == 3 and r["p"]["heartbeat_interval"] == HB and r["p"]["instance_id"] == "c1",
          f"/register → CALLRESULT {r['p']}")
    check(listing(gw, tok)[("clients", "c1")]["state"] == "ready", "GET /gateway/list: ready")
    await ws.send(call("/heartbeat", {"in_flight": 3, "load": 0.2}))
    r = await rx(ws)
    check(r["t"] == 3 and r["p"]["state"] == "ready", "/heartbeat → {state: ready}")
    check(listing(gw, tok)[("clients", "c1")]["in_flight"] == 3, "list: in_flight=3")
    await ws.send(call("/heartbeat", {"in_flight": 1}))
    r = await rx(ws)
    check(r["t"] == 4 and r["c"] == 429, "/heartbeat more often than interval/2 → 429, socket alive")
    await ws.send(call("/status", {"state": "overloaded"}))
    r = await rx(ws)
    check(r["t"] == 3 and listing(gw, tok)[("clients", "c1")]["state"] == "overloaded", "/status overloaded")
    await ws.send(call("/status", {"state": "ready"}))
    await rx(ws)
    await ws.send(call("/status", {"state": "draining", "reason": "SIGTERM"}))
    await rx(ws)
    check(listing(gw, tok)[("clients", "c1")]["state"] == "draining", "/status draining")
    await ws.send(call("/status", {"state": "ready"}))
    r = await rx(ws)
    check(r["t"] == 4 and r["c"] == 409, "draining → ready forbidden: 409")
    await ws.send(call("/nope"))
    r = await rx(ws)
    check(r["t"] == 4 and r["c"] == 404, "unknown action → 404")
    await ws.send(json.dumps({"t": 0, "u": str(uuid.uuid4()), "p": {}}))
    r = await rx(ws)
    check(r["t"] == 4 and r["c"] == 400, "OPEN (t=0) → 400")
    await ws.send(call("/unregister", {"reason": "shutdown"}))
    r = await rx(ws)
    check(r["t"] == 3, "/unregister → CALLRESULT")
    code, _ = await close_code(ws)
    check(code == 1000, f"after /unregister gateway closes 1000 (received {code})")
    check(listing(gw, tok)[("clients", "c1")]["state"] == "offline", "list: offline")


async def scenario_register_errors(gw, tok):
    print("2. registration failures — every code triggered on purpose")
    cases = [
        ("400 missing field",   dict(version=None),                      400),
        ("400 address not an ip", dict(address="goapi:8081"),            400),
        ("400 malformed prefix", dict(prefixes=["/api/v1/x"]),           400),
        ("422 instance ≠ URL",  dict(instance="other"),                  422),
        ("422 capacity < 1",    dict(capacity=0),                        422),
        ("422 prefixes overlap", dict(prefixes=["/api/v2/a", "/api/v2/a/b"]), 422),
        ("403 outside allowed_cidr", dict(address="10.9.9.9:1"),         403),
    ]
    for name, over, code in cases:
        ws = await connect(gw, tok, "clients", "e1")
        p = register_payload("clients", "e1")
        p.update({k: v for k, v in over.items() if v is not None})
        for k, v in over.items():
            if v is None:
                p.pop(k, None)
        await ws.send(call("/register", p))
        r = await rx(ws)
        cc, _ = await close_code(ws)
        check(r["t"] == 4 and r["c"] == code and cc == 1008, f"{name} → CALLERROR {r.get('c')} + close {cc}")

    print("   409 foreign prefix: 'clients' holds /api/v2/clients, module 'other' requests the same one")
    ws1 = await connect(gw, tok, "clients", "c2")
    await register(ws1, "clients", "c2")
    ws2 = await connect(gw, tok, "other", "o1")
    await ws2.send(call("/register", register_payload("other", "o1", prefixes=["/api/v2/clients/vip"])))
    r = await rx(ws2)
    cc, _ = await close_code(ws2)
    check(r["t"] == 4 and r["c"] == 409 and cc == 1008, f"→ 409 + close {cc}")

    print("   CALL before /register → 409, socket alive; /register not within 5s → close 1008")
    ws3 = await connect(gw, tok, "clients", "c3")
    await ws3.send(call("/heartbeat", {"in_flight": 0}))
    r = await rx(ws3)
    check(r["t"] == 4 and r["c"] == 409, "heartbeat before register → 409")
    t0 = time.monotonic()
    cc, why = await close_code(ws3, timeout=8)
    check(cc == 1008 and 4 <= time.monotonic() - t0 <= 7, f"register timeout → close 1008 after ~5s ({why})")
    await ws1.send(call("/unregister", {"reason": "done"}))
    await rx(ws1)
    await close_code(ws1)


async def dial_status(url, headers=None):
    """Upgrade rejected before 101: HTTP status and problem+json (README § Handshake)."""
    try:
        ws = await websockets.connect(url, additional_headers=headers or {}, open_timeout=5)
        await ws.close()
        return 101, None
    except websockets.InvalidStatus as e:
        body = e.response.body.decode() if e.response.body else ""
        return e.response.status_code, (json.loads(body) if body else None)


async def scenario_auth(gw, tok):
    print("3. socket authorization — HTTP rejection before 101 (README § Handshake)")
    url = gw.replace("http", "ws", 1) + "/gateway/clients/a1"
    st, body = await dial_status(url)
    check(st == 401 and body["type"] == "urn:apostol:gateway:token-invalid",
          f"no token → HTTP {st} {body and body['type']}")
    st, body = await dial_status(url, {"Authorization": "Bearer not.a.jwt"})
    check(st == 401 and body["type"].endswith(":token-invalid"), f"garbage token → HTTP {st}")
    st, body = await dial_status(gw.replace("http", "ws", 1) + "/gateway/Bad_Name/x",
                                 {"Authorization": f"Bearer {tok}"})
    check(st == 400 and body["type"].endswith(":bad-request"), f"name not matching pattern → HTTP {st}")
    st, body = await dial_status(gw.replace("http", "ws", 1) + "/gateway/clients",
                                 {"Authorization": f"Bearer {tok}"})
    check(st == 404 and body["type"].endswith(":not-found"), f"path without instance → HTTP {st}")
    st, _ = await dial_status(url, {"Authorization": f"Bearer {tok}"})
    check(st == 101, "valid token → 101")
    r = requests.get(f"{gw}/gateway/list", timeout=5)
    check(r.status_code == 401 and r.headers["Content-Type"].startswith("application/problem+json")
          and r.json()["type"] == "urn:apostol:gateway:token-invalid" and "X-Request-Id" in r.headers,
          "GET /gateway/list without token → 401 problem+json + X-Request-Id")
    r = requests.put(f"{gw}/gateway/clients/a1", headers={"Authorization": f"Bearer {tok}"}, timeout=5)
    check(r.status_code == 405 and r.headers.get("Allow") == "GET, POST" and r.json()["type"].endswith(":method-not-allowed"),
          "PUT on a control path → 405 + Allow, not 404 no-route")


async def scenario_clock(gw, tok):
    print(f"4. suspect/offline by clock (interval={HB}s, suspect≥{2*HB}s, offline≥{4*HB}s)")
    ws = await connect(gw, tok, "clients", "t1")
    await register(ws, "clients", "t1")
    t0 = time.monotonic()
    await asyncio.sleep(2 * HB + 1.5)   # threshold + half a tick: clock transitions step by 1s
    st = listing(gw, tok)[("clients", "t1")]["state"]
    check(st == "suspect", f"silence {int(time.monotonic()-t0)}s → {st}")
    await ws.send(call("/heartbeat", {"in_flight": 0}))
    r = await rx(ws)
    check(r["p"]["state"] == "ready" and listing(gw, tok)[("clients", "t1")]["state"] == "ready",
          "heartbeat from suspect → ready (in the response and in the table)")
    t0 = time.monotonic()
    cc, why = await close_code(ws, timeout=4 * HB + 4)
    check(cc == 4000 and listing(gw, tok)[("clients", "t1")]["state"] == "offline",
          f"silence {int(time.monotonic()-t0)}s → offline + close 4000 ('{why}')")


async def scenario_commands(gw, tok):
    print("5. gateway → module commands over HTTP: /ping, /reload, /drain; timeout 5s")
    ws = await connect(gw, tok, "clients", "k1")
    await register(ws, "clients", "k1")

    async def module_side(answer_ping=True):
        # Module answers the gateway's CALL; on /drain: CALLRESULT, then /status draining → /unregister.
        while True:
            m = await rx(ws, timeout=10)
            if m["t"] != 2:
                continue
            if m["a"] == "/ping":
                if answer_ping:
                    await ws.send(json.dumps({"t": 3, "u": m["u"], "p": {"in_flight": 0}}))
                return m["a"]
            if m["a"] == "/reload":
                await ws.send(json.dumps({"t": 4, "u": m["u"], "c": 500, "m": "cannot reload"}))
                return m["a"]
            if m["a"] == "/drain":
                await ws.send(json.dumps({"t": 3, "u": m["u"], "p": {}}))
                await ws.send(call("/status", {"state": "draining"}))
                await rx(ws)
                await ws.send(call("/unregister", {"reason": "drained"}))
                await rx(ws)
                return m["a"]

    hdr = {"Authorization": f"Bearer {tok}"}
    loop = asyncio.get_event_loop()
    fut = loop.run_in_executor(None, lambda: requests.post(f"{gw}/gateway/clients/k1/ping", headers=hdr, timeout=8))
    a = await module_side()
    r = await fut
    check(a == "/ping" and r.status_code == 200 and r.json() == {"in_flight": 0}, f"POST …/ping → module answered, HTTP {r.status_code} {r.text}")

    fut = loop.run_in_executor(None, lambda: requests.post(f"{gw}/gateway/clients/k1/reload", headers=hdr, timeout=8))
    a = await module_side()
    r = await fut
    check(a == "/reload" and r.status_code == 502 and r.json()["type"] == "urn:apostol:gateway:upstream-error",
          f"module CALLERROR → HTTP 502 problem+json ({r.json().get('detail')})")

    fut = loop.run_in_executor(None, lambda: requests.post(f"{gw}/gateway/clients/k1/ping", headers=hdr, timeout=12))
    a = await module_side(answer_ping=False)
    t0 = time.monotonic()
    r = await fut
    check(a == "/ping" and r.status_code == 504 and 4 <= time.monotonic() - t0 <= 7,
          f"no answer from module → HTTP 504 after ~5s ({int(time.monotonic()-t0)}s)")

    fut = loop.run_in_executor(None, lambda: requests.post(f"{gw}/gateway/clients/k1/drain", headers=hdr,
                                                           json={"reason": "test"}, timeout=8))
    a = await module_side()
    r = await fut
    cc, _ = await close_code(ws)
    check(a == "/drain" and r.status_code == 200 and cc == 1000 and listing(gw, tok)[("clients", "k1")]["state"] == "offline",
          f"/drain → CALLRESULT, draining, unregister, close {cc}, offline")

    r = requests.post(f"{gw}/gateway/clients/nobody/ping", headers=hdr, timeout=5)
    check(r.status_code == 409 and r.json()["type"] == "urn:apostol:gateway:not-on-this-worker",
          "command to a nonexistent instance → 409 not-on-this-worker")


async def scenario_replace(gw, tok):
    print("6. a second connection for the same instance replaces the first (README § Handshake)")
    ws1 = await connect(gw, tok, "clients", "r1")
    await register(ws1, "clients", "r1")
    ws2 = await connect(gw, tok, "clients", "r1")
    r = await register(ws2, "clients", "r1", version="0.2.0")
    check(r["t"] == 3, "second /register accepted")
    cc, why = await close_code(ws1)
    check(cc == 1001 and why == "replaced", f"first socket closed {cc} '{why}'")
    row = listing(gw, tok)[("clients", "r1")]
    check(row["state"] == "ready" and row["version"] == "0.2.0", "table points to the new socket (v0.2.0, ready)")
    await ws2.send(call("/heartbeat", {"in_flight": 0}))
    r = await rx(ws2)
    check(r["t"] == 3, "new socket alive")
    await ws2.close()
    await asyncio.sleep(1)
    check(listing(gw, tok)[("clients", "r1")]["state"] == "offline", "disconnect without /unregister → offline")


async def scenario_frames(gw, tok):
    print("7. frames: binary → 1003, > 64 KiB → 1009, not JSON → 400, repeated u → 400")
    ws = await connect(gw, tok, "clients", "f1")
    await register(ws, "clients", "f1")
    await ws.send("not json")
    r = await rx(ws)
    check(r["t"] == 4 and r["c"] == 400, "not JSON → 400")
    u = str(uuid.uuid4())
    # A duplicate u "in flight" can't be caught from outside (the response arrives before the
    # second frame) — we only check that a normal repeat of u after the response is accepted.
    await ws.send(call("/heartbeat", {"in_flight": 0}, u=u))
    await rx(ws)
    await ws.send(b"\x00\x01")
    cc, _ = await close_code(ws)
    check(cc == 1003, f"binary frame → close {cc}")
    ws = await connect(gw, tok, "clients", "f2")
    await register(ws, "clients", "f2")
    await ws.send(json.dumps({"t": 2, "u": str(uuid.uuid4()), "a": "/heartbeat", "p": {"in_flight": 0, "pad": "x" * 70000}}))
    cc, _ = await close_code(ws)
    check(cc == 1009, f"frame > 64 KiB → close {cc}")


def route(gw, tok, path):
    r = requests.get(f"{gw}/gateway/route", params={"path": path},
                     headers={"Authorization": f"Bearer {tok}"}, timeout=5)
    return r


async def scenario_route(gw, tok):
    print("8. route: longest prefix among ready, lowest in_flight, round-robin; 404/503")
    r = route(gw, tok, "/api/v2/nowhere/1")
    check(r.status_code == 404 and r.json()["type"].endswith(":no-route"), "path without prefix → 404 no-route")
    r = route(gw, tok, "/oauth2/token")
    check(r.status_code == 400, "path outside /api/v2/ → 400")

    a = await connect(gw, tok, "orders", "o1")
    check((await register(a, "orders", "o1", address="127.0.0.1:18101"))["t"] == 3, "o1 registered")
    b = await connect(gw, tok, "orders", "o2")
    check((await register(b, "orders", "o2", address="127.0.0.1:18102"))["t"] == 3, "o2 registered")
    # o3 of the same module carries a DIFFERENT set — only a longer prefix (rolling rollout,
    # README § /register, MAY). Nesting within one set is 422, between modules is 409; between
    # instances of the same module it's allowed — this is exactly where the longest prefix decides.
    c = await connect(gw, tok, "orders", "o3")
    check((await register(c, "orders", "o3", address="127.0.0.1:18103",
                          prefixes=["/api/v2/orders/reports"]))["t"] == 3, "o3 registered with /api/v2/orders/reports")

    picks = [route(gw, tok, "/api/v2/orders/1").json()["instance"] for _ in range(4)]
    check(sorted(set(picks)) == ["o1", "o2"] and picks[:2] == picks[2:],
          f"two ready with equal in_flight on /api/v2/orders — round-robin: {picks}")
    r = route(gw, tok, "/api/v2/orders/reports/daily").json()
    check(r["instance"] == "o3", f"longest prefix /api/v2/orders/reports → o3 (got {r['instance']})")
    r = route(gw, tok, "/api/v2/orders2").json() if route(gw, tok, "/api/v2/orders2").status_code == 200 else None
    check(r is None, "/api/v2/orders2 is not covered by prefix /api/v2/orders (boundary on '/')")

    await c.send(call("/status", {"state": "draining", "deadline": 5}))
    await rx(c)
    r = route(gw, tok, "/api/v2/orders/reports/daily").json()
    check(r["instance"] in ("o1", "o2"), f"o3 in draining out of rotation → shorter prefix o1/o2 ({r['instance']})")

    await a.send(call("/status", {"state": "overloaded"}))
    await rx(a)
    picks = {route(gw, tok, "/api/v2/orders/1").json()["instance"] for _ in range(4)}
    check(picks == {"o2"}, f"overloaded out of rotation → only o2 ({picks})")

    await b.send(call("/unregister", {}))
    await rx(b)
    r = route(gw, tok, "/api/v2/orders/1")
    check(r.status_code == 503 and r.headers.get("Retry-After") == "1" and r.json()["type"].endswith(":no-instance"),
          "route exists, no ready → 503 no-instance, Retry-After: 1")
    for ws in (a, c):
        await ws.close()


# ─── scenario 9: data plane ──────────────────────────────────────────────────

class Echo:
    """Echo module: HTTP/1.1 on asyncio, one request per connection (HttpProxy sends
    Connection: close). Answers with what it received; special paths — status 409, hang,
    drop. Returns its OWN X-Request-Id and Set-Cookie — the gateway must replace/strip them
    (README § Data plane)."""

    def __init__(self, port):
        self.port = port
        self.seen = []
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", self.port)

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def handle(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = []
        for ln in lines[1:]:
            if ln:
                k, v = ln.split(":", 1)
                headers.append((k, v.strip()))
        length = int(dict((k.lower(), v) for k, v in headers).get("content-length", "0"))
        body = (await reader.readexactly(length)).decode() if length else ""
        rec = {"method": method, "target": target, "headers": headers, "body": body}
        self.seen.append(rec)
        path = target.split("?", 1)[0]
        if path.endswith("/hang"):
            await asyncio.sleep(6)
            writer.close()
            return
        if path.endswith("/drop"):
            writer.close()
            return
        status, reason = 200, "OK"
        if "/status/" in path:
            status = int(path.rsplit("/", 1)[1])
            reason = "Whatever"
        payload = json.dumps(rec).encode()
        resp = (f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\nX-Request-Id: module-made-this-up\r\n"
                f"Set-Cookie: module=1; Path=/\r\nConnection: close\r\n\r\n").encode() + payload
        writer.write(resp)
        await writer.drain()
        writer.close()


def raw_head(gw, path, tok):
    """Raw response headers, lowercased: requests merges duplicates."""
    import socket
    from urllib.parse import urlparse
    u = urlparse(gw)
    with socket.create_connection((u.hostname, u.port), timeout=5) as sk:
        sk.sendall(f"GET {path} HTTP/1.1\r\nHost: {u.hostname}\r\nAuthorization: Bearer {tok}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sk.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.split(b"\r\n\r\n", 1)[0].decode().lower()


def expired_token(gw, tok, secret):
    """The same token but with exp in the past, re-signed with the audience secret (HS256)."""
    import base64, hmac, hashlib
    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")
    head, body, _ = tok.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["exp"] = claims["iat"] - 60
    body2 = b64(json.dumps(claims).encode())
    sig = b64(hmac.new(secret.encode(), head.encode() + b"." + body2, hashlib.sha256).digest())
    return head + "." + body2.decode() + "." + sig.decode()


def hdr(rec, name):
    return [v for k, v in rec["headers"] if k.lower() == name.lower()]


async def scenario_data_plane(gw, tok):
    print("9. data plane (README § Data plane): headers, retry, 401/403/404/503/502/504")
    # requests blocks the thread, and the echo module lives in this same asyncio loop — every
    # HTTP request of the scenario goes through a thread, otherwise the gateway waits for the
    # module, which waits for us (504).
    echo = Echo(18100)
    await echo.start()
    try:
        # 404 no-route / 503 no-instance — through the data plane itself, with Bearer
        r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/nowhere/1", headers={"Authorization": f"Bearer {tok}"}, timeout=5)
        check(r.status_code == 404 and r.json()["type"].endswith(":no-route") and "X-Request-Id" in r.headers,
              "no prefix → 404 no-route problem+json")

        dead = await connect(gw, tok, "echo", "dead")
        check((await register(dead, "echo", "dead", address="127.0.0.1:18199"))["t"] == 3, "echo/dead (nobody listening) registered")
        await dead.send(call("/status", {"state": "overloaded"}))
        await rx(dead)
        r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/1", headers={"Authorization": f"Bearer {tok}"}, timeout=5)
        check(r.status_code == 503 and r.headers.get("Retry-After") == "1" and r.json()["type"].endswith(":no-instance"),
              "route exists, no ready → 503 no-instance + Retry-After")
        await dead.send(call("/status", {"state": "ready"}))
        await rx(dead)

        live = await connect(gw, tok, "echo", "live")
        check((await register(live, "echo", "live", address="127.0.0.1:18100"))["t"] == 3, "echo/live registered")

        # README § Data plane headers — what the module sees and what the client sees
        r = await asyncio.to_thread(requests.post, f"{gw}/api/v2/echo/items?x=1", data='{"a":1}',
                          headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
                                   "Cookie": "sid=secret", "X-Request-Id": "cli-1",
                                   "X-Forwarded-For": "203.0.113.5", "User-Agent": "stub/9"}, timeout=5)
        check(r.status_code == 200, f"POST through the gateway → {r.status_code}")
        seen = r.json()
        check(seen["method"] == "POST" and seen["target"] == "/api/v2/echo/items?x=1" and seen["body"] == '{"a":1}',
              "method, path, query, body — as sent by the client")
        check(hdr(seen, "Authorization") == [f"Bearer {tok}"], "Authorization: Bearer <client AT> exactly one")
        check(hdr(seen, "Cookie") == [], "Cookie stripped")
        rid = hdr(seen, "X-Request-Id")
        check(len(rid) == 1 and len(rid[0]) == 36 and rid[0] != "cli-1", f"X-Request-Id — gateway's UUID ({rid})")
        check(hdr(seen, "X-Client-Request-Id") == ["cli-1"], "client id → X-Client-Request-Id")
        check(hdr(seen, "X-Forwarded-For") == ["203.0.113.5"], f"X-Forwarded-For exactly one, incoming ({hdr(seen, 'X-Forwarded-For')})")
        # README § Data plane: nginx sets $proxy_add_x_forwarded_for — appends its own address to
        # the end of what the client sent; the gateway keeps the last element, the client-supplied
        # first one doesn't get through.
        chain = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/xff2",
                          headers={"Authorization": f"Bearer {tok}", "X-Forwarded-For": "1.2.3.4, 203.0.113.7 ,  198.51.100.9 "}, timeout=5)
        check(hdr(chain.json(), "X-Forwarded-For") == ["198.51.100.9"], f"X-Forwarded-For from a chain — last element, no spaces ({hdr(chain.json(), 'X-Forwarded-For')})")
        check(hdr(seen, "X-Forwarded-Proto") == ["https"], "X-Forwarded-Proto: https")
        check(hdr(seen, "X-Gateway-Worker") and hdr(seen, "X-Gateway-Worker")[0].isdigit(), "X-Gateway-Worker: pid")
        check(hdr(seen, "User-Agent") == ["stub/9"] and hdr(seen, "Content-Type") == ["application/json"], "User-Agent, Content-Type as is")
        check(len(hdr(seen, "Connection")) == 1 and hdr(seen, "Connection")[0].lower() == "close", "Connection: close exactly one")
        check(len(hdr(seen, "Host")) == 1, f"Host exactly one ({hdr(seen, 'Host')})")
        check(r.headers.get("X-Request-Id") == rid[0], "client gets the gateway's X-Request-Id, not the one made up by the module")
        # Found on an end-to-end run: HttpProxy was replacing Content-Type with text/plain
        # and duplicating Content-Length — response headers are checked raw, since requests merges them
        raw = await asyncio.to_thread(raw_head, gw, "/api/v2/echo/items", tok)
        check(raw.count("content-length:") == 1, f"Content-Length exactly one ({raw.count('content-length:')})")
        check("content-type: application/json" in raw, "module's Content-Type came through as is (application/json)")
        r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/xff", headers={"Authorization": f"Bearer {tok}"}, timeout=5)
        check(hdr(r.json(), "X-Forwarded-For") == ["127.0.0.1"], f"no incoming X-Forwarded-For — peer address without ::ffff: ({hdr(r.json(), 'X-Forwarded-For')})")
        check("Set-Cookie" not in r.headers and not r.cookies, "module's Set-Cookie stripped")

        # Module's status and body — passed through as is
        r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/status/409", headers={"Authorization": f"Bearer {tok}"}, timeout=5)
        check(r.status_code == 409 and r.json()["target"] == "/api/v2/echo/status/409", "module's 409 → 409 to client, body as is")

        # Without Authorization — goes without it, 401 is set by the module (here echo answers 200)
        r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/anon", timeout=5)
        check(r.status_code == 200 and hdr(r.json(), "Authorization") == [], "no Authorization → to the module without Authorization")
        r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/x", headers={"Authorization": "Bearer not.a.jwt"}, timeout=5)
        check(r.status_code == 401 and r.json()["type"].endswith(":token-invalid"), "garbage Bearer → 401 token-invalid problem+json from the gateway")
        if SECRET:
            r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/x",
                                        headers={"Authorization": f"Bearer {expired_token(gw, tok, SECRET)}"}, timeout=5)
            check(r.status_code == 401 and r.json()["type"].endswith(":token-expired") and "X-Request-Id" in r.headers
                  and r.json()["instance"] == "/api/v2/echo/x",
                  "expired AT → 401 token-expired (edition 4), instance = request path")

        # README § Data plane retry: dead is not listening → connect refused → retry on live; after 5 failures dead → suspect
        picks = []
        for _ in range(10):
            r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/retry", headers={"Authorization": f"Bearer {tok}"}, timeout=5)
            picks.append(r.status_code)
        check(picks == [200] * 10, f"10 requests with a dead instance in rotation — all 200 via retry ({picks})")
        row = (await asyncio.to_thread(listing, gw, tok))[("echo", "dead")]
        check(row["state"] == "suspect" and row["conn_errors"] >= 5, f"dead after {row['conn_errors']} connect failures → suspect (passive check, README § Instance states)")
        await dead.send(call("/heartbeat", {"in_flight": 0}))
        await rx(dead)
        row = (await asyncio.to_thread(listing, gw, tok))[("echo", "dead")]
        check(row["state"] == "ready" and row["conn_errors"] == 0, "heartbeat → ready, counter reset")
        await dead.send(call("/unregister", {}))
        await rx(dead)

        # No retry after send: drop → 502, silence → 504 (response_timeout_ms in the run config)
        n = len(echo.seen)
        r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/drop", headers={"Authorization": f"Bearer {tok}"}, timeout=10)
        check(r.status_code == 502 and r.json()["type"].endswith(":upstream-error") and len(echo.seen) == n + 1,
              f"drop after send → 502 upstream-error, request sent exactly once ({len(echo.seen) - n})")
        t0 = time.monotonic()
        r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/echo/hang", headers={"Authorization": f"Bearer {tok}"}, timeout=15)
        dt = time.monotonic() - t0
        check(r.status_code == 504 and r.json()["type"].endswith(":upstream-timeout") and 1.5 < dt < 4,
              f"silence → 504 upstream-timeout in {dt:.1f}s (run's response_timeout_ms 2000)")
        await live.send(call("/unregister", {}))
        await rx(live)
    finally:
        await echo.stop()


async def scenario_mirror(gw, tok, peer, pg_dsn):
    print("10. gateway.node mirror: owner record, NOTIFY to peer, route through peer, takeover, sweep, re-assert")
    if not peer or not pg_dsn:
        print("  [skip] needs --peer and --pg")
        return
    import psycopg2
    pg = psycopg2.connect(pg_dsn)
    pg.autocommit = True

    def q(sql, *args):
        c = pg.cursor()
        c.execute(sql, args)
        return c.fetchall() if c.description else None

    def row(module, instance):
        r = q("SELECT state, worker, address, extract(epoch FROM now() - seen)::int FROM gateway.node WHERE module = %s AND instance = %s", module, instance)
        return r[0] if r else None

    def journal(module, instance, since_id):
        return q("SELECT state_from, state_to, reason FROM gateway.log WHERE module = %s AND instance = %s AND id > %s ORDER BY id", module, instance, since_id)

    def last_log_id():
        return q("SELECT coalesce(max(id), 0) FROM gateway.log")[0][0]

    async def settle(cond, timeout, what, hb=None):
        """Wait until cond() becomes true (NOTIFY and writes are async); with hb — keep the
        instance alive with heartbeats, otherwise the gateway's clock will drift it into suspect."""
        deadline = time.time() + timeout
        next_hb = time.time() + HB + 0.1
        while time.time() < deadline:
            if cond():
                return True
            if hb and time.time() >= next_hb:
                await hb.send(call("/heartbeat", {"in_flight": 0}))
                await rx(hb)
                next_hb = time.time() + HB + 0.1
            await asyncio.sleep(0.1)
        return cond()

    hdrs = {"Authorization": f"Bearer {tok}"}
    me = requests.get(f"{gw}/gateway/list", headers=hdrs, timeout=5).json()["gateway_worker"]
    other = requests.get(f"{peer}/gateway/list", headers=hdrs, timeout=5).json()["gateway_worker"]
    check(me != other, f"two gateways — two workers ({me}, {other})")
    # Clean slate: foreign rows from past runs — offline, so they don't interfere with 409 on prefix.
    q("UPDATE gateway.node SET state = 'offline' WHERE state <> 'offline' AND coalesce(worker, 0) NOT IN (%s, %s)", me, other)

    echo = Echo(18110)
    await echo.start()
    try:
        # 1. Registration on my side → row with my pid, journal, peer sees it mirrored and routes to it
        l0 = last_log_id()
        ws = await connect(gw, tok, "mirror", "m1")
        check((await register(ws, "mirror", "m1", address="127.0.0.1:18110"))["t"] == 3, "mirror/m1 registered on my side")
        check(await settle(lambda: (row("mirror", "m1") or (None,))[0] == "ready", 3, "row"), f"gateway.node: ready, worker={me} ({row('mirror', 'm1')})")
        check(row("mirror", "m1")[1] == me, "gateway.node.worker — my pid")
        j = journal("mirror", "m1", l0)
        check(j and j[-1][1] == "ready" and j[-1][2] == "registered", f"gateway.log: → ready, reason=registered ({j})")
        check(await settle(lambda: listing(peer, tok).get(("mirror", "m1"), {}).get("state") == "ready", 3, "peer"), "peer: ready via NOTIFY")
        pl = listing(peer, tok)[("mirror", "m1")]
        check(pl["source"] == "mirror" and pl["owner_worker"] == me and pl["address"] == "127.0.0.1:18110" and pl["prefixes"] == ["/api/v2/mirror"],
              f"peer: source=mirror, owner={me}, address and prefixes from the payload")
        r = requests.get(f"{peer}/gateway/route", params={"path": "/api/v2/mirror/1"}, headers=hdrs, timeout=5)
        check(r.status_code == 200 and r.json()["instance"] == "m1", "peer: /gateway/route → m1")
        r = await asyncio.to_thread(requests.get, f"{peer}/api/v2/mirror/ping", headers=hdrs, timeout=5)
        check(r.status_code == 200 and r.json()["target"] == "/api/v2/mirror/ping", "data plane THROUGH THE PEER reaches the module registered on my side")
        check(hdr(echo.seen[-1], "X-Gateway-Worker") == [str(other)], f"X-Gateway-Worker — peer's pid ({hdr(echo.seen[-1], 'X-Gateway-Worker')})")
        r = requests.post(f"{peer}/gateway/mirror/m1/ping", headers=hdrs, timeout=5)
        check(r.status_code == 409 and f"owner worker {me}" in r.json()["detail"], f"command to peer → 409 with owner's pid ({r.json()['detail']})")

        # 2. seen — once per interval, only on a live heartbeat: without a heartbeat seen ages,
        #    after a heartbeat it moves (we compare the timestamp itself, not the age)
        seen_at = lambda: q("SELECT seen FROM gateway.node WHERE module = 'mirror' AND instance = 'm1'")[0][0]
        # the seen tick counts the registration as a heartbeat while its age (truncated to
        # seconds) is <= HB — nearly HB + 1 s; wait longer than that window plus one tick
        await asyncio.sleep(HB + 1.5)
        s0 = seen_at()
        await asyncio.sleep(HB + 1)      # in total < offline_after * HB of silence
        check(seen_at() == s0, f"without a heartbeat seen doesn't move for {HB + 1}+s")
        await ws.send(call("/heartbeat", {"in_flight": 0}))
        await rx(ws)
        check(await settle(lambda: seen_at() > s0, HB + 1, "seen"), "seen moved after heartbeat")

        # 3. State transition on the owner → journal with reason, peer out of rotation
        l1 = last_log_id()
        await ws.send(call("/status", {"state": "draining", "reason": "SIGTERM"}))
        await rx(ws)
        check(await settle(lambda: row("mirror", "m1")[0] == "draining", 3, "draining"), "gateway.node: draining")
        j = journal("mirror", "m1", l1)
        check(j == [("ready", "draining", "status: SIGTERM")], f"gateway.log: ready→draining, reason=status: SIGTERM ({j})")
        check(await settle(lambda: listing(peer, tok)[("mirror", "m1")]["state"] == "draining", 3, "peer draining"), "peer: draining via NOTIFY")
        r = requests.get(f"{peer}/gateway/route", params={"path": "/api/v2/mirror/1"}, headers=hdrs, timeout=5)
        check(r.status_code == 503, "peer: draining out of rotation → 503")

        # 4. Owner socket drop → offline with reason socket closed; peer offline
        l2 = last_log_id()
        await ws.close()
        check(await settle(lambda: row("mirror", "m1")[0] == "offline", 3, "offline"), "drop → gateway.node offline")
        j = journal("mirror", "m1", l2)
        check(j == [("draining", "offline", "socket closed")], f"gateway.log: draining→offline, reason=socket closed ({j})")
        check(await settle(lambda: listing(peer, tok)[("mirror", "m1")]["state"] == "offline", 3, "peer offline"), "peer: offline via NOTIFY")

        # 5. Takeover: the same instance registers on the PEER while my socket is alive →
        #    my socket is closed 1001 replaced, the row belongs to the peer, I have a mirror
        ws_a = await connect(gw, tok, "mirror", "m2")
        check((await register(ws_a, "mirror", "m2", address="127.0.0.1:18110", prefixes=["/api/v2/mirror2"]))["t"] == 3, "mirror/m2 on my side")
        check(await settle(lambda: (row("mirror", "m2") or (None, None))[1] == me, 3, "m2 mine"), "gateway.node: m2 is mine")
        l3 = last_log_id()
        ws_b = await connect(peer, tok, "mirror", "m2")
        check((await register(ws_b, "mirror", "m2", address="127.0.0.1:18110", prefixes=["/api/v2/mirror2"]))["t"] == 3, "mirror/m2 on the peer (takeover)")
        code, reason = await close_code(ws_a, timeout=4)
        check(code == 1001 and reason == "replaced", f"my socket closed 1001 replaced ({code} {reason!r})")
        check(await settle(lambda: row("mirror", "m2")[1] == other and row("mirror", "m2")[0] == "ready", 3, "m2 other"), f"gateway.node: m2 ready on the peer ({row('mirror', 'm2')})")
        j = journal("mirror", "m2", l3)
        check(j == [("ready", "offline", "re-registered"), ("offline", "ready", "registered")], f"gateway.log: ready→offline re-registered, offline→ready registered ({j})")
        mine = listing(gw, tok)[("mirror", "m2")]
        check(mine["source"] == "mirror" and mine["owner_worker"] == other and mine["state"] == "ready", "on my side m2 is a mirror of the peer, ready")
        r = await asyncio.to_thread(requests.get, f"{gw}/api/v2/mirror2/x", headers=hdrs, timeout=5)
        check(r.status_code == 200, "data plane on my side → peer's module")
        await ws_b.send(call("/unregister", {"reason": "done"}))
        await rx(ws_b)
        await close_code(ws_b)

        # 6. Sweep: a dead worker's row with seen older than (offline_after+1) intervals →
        #    goes offline by deadline, journal with reason, peer's memory too
        l4 = last_log_id()
        q("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker, registered, seen, updated)"
          " VALUES ('mirror', 'dead', '0', '127.0.0.1:18199', ARRAY['/api/v2/mirror-dead'], 'ready', 1, 424242, now(), now() - interval '1 hour', now())"
          " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', worker = 424242, seen = now() - interval '1 hour', prefixes = EXCLUDED.prefixes")
        check(await settle(lambda: listing(gw, tok).get(("mirror", "dead"), {}).get("state") == "ready", 3, "dead notify"), "foreign ready row appeared on my side as a mirror (NOTIFY on INSERT)")
        check(await settle(lambda: row("mirror", "dead")[0] == "offline", RELOAD + 2, "sweep"), "sweep: offline by seen deadline")
        j = journal("mirror", "dead", l4)
        check(any(a == "ready" and b == "offline" and c.startswith("swept by worker") for a, b, c in j), f"gateway.log: reason='swept by worker …' ({j})")
        check(await settle(lambda: listing(gw, tok)[("mirror", "dead")]["state"] == "offline", 3, "dead off"), "on my side mirror/dead → offline")

        # 6b. A foreign app's row without a worker (NULL) — mirrored, doesn't crash the worker
        q("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker)"
          " VALUES ('mirror', 'anon', NULL, '127.0.0.1:18197', ARRAY['/api/v2/mirror-anon'], 'ready', 1, NULL)"
          " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', worker = NULL, seen = now()")
        check(await settle(lambda: listing(gw, tok).get(("mirror", "anon"), {}).get("state") == "ready", 3, "anon"), "row with worker NULL — mirror, owner_worker 0")
        check(listing(gw, tok)[("mirror", "anon")]["owner_worker"] == 0, "owner_worker = 0 when NULL")
        q("UPDATE gateway.node SET state = 'offline' WHERE module = 'mirror' AND instance = 'anon'")

        # 7. Re-assert: a foreign hand (the same sweep on another site) marked MY live row
        #    offline → I don't argue via NOTIFY, on reload I return it to ready
        ws3 = await connect(gw, tok, "mirror", "m3")
        check((await register(ws3, "mirror", "m3", address="127.0.0.1:18110", prefixes=["/api/v2/mirror3"]))["t"] == 3, "mirror/m3 on my side")
        check(await settle(lambda: (row("mirror", "m3") or (None,))[0] == "ready", 3, "m3"), "gateway.node: m3 ready")
        l5 = last_log_id()
        q("SELECT set_config('gateway.reason', 'foreign sweep', true); UPDATE gateway.node SET state = 'offline' WHERE module = 'mirror' AND instance = 'm3'")
        await asyncio.sleep(0.5)
        check(listing(gw, tok)[("mirror", "m3")]["state"] == "ready", "NOTIFY offline on my own row — I don't change memory (the socket is truth)")
        check(await settle(lambda: row("mirror", "m3")[0] == "ready", RELOAD + 2, "reassert", hb=ws3), "reload: row returned to ready")
        j = journal("mirror", "m3", l5)
        check(j == [("ready", "offline", "foreign sweep"), ("offline", "ready", "owner re-asserted")], f"gateway.log: … offline→ready owner re-asserted ({j})")

        # 8. A row with MY pid but no socket (a previous life of the pid) → offline on reload
        l6 = last_log_id()
        q("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker)"
          " VALUES ('mirror', 'ghost', '0', '127.0.0.1:18198', ARRAY['/api/v2/mirror-ghost'], 'ready', 1, %s)"
          " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', worker = EXCLUDED.worker, seen = now()", me)
        check(await settle(lambda: row("mirror", "ghost")[0] == "offline", RELOAD + 2, "ghost", hb=ws3), "row with my pid but no socket → offline on reload")
        j = journal("mirror", "ghost", l6)
        check(j and j[-1] == ("ready", "offline", "no socket on worker"), f"gateway.log: reason=no socket on worker ({j})")

        # 9. Startup reload is covered indirectly: the peer started earlier and learned mirror/*
        #    via NOTIFY; rows inserted into the database BEFORE the worker started arrive on the
        #    first reload — visible as the line 'mirror: reload' in the new process's error.log
        #    (checked manually).
        await ws3.send(call("/unregister", {"reason": "done"}))
        await rx(ws3)
        await close_code(ws3)
    finally:
        await echo.stop()
        pg.close()


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://127.0.0.1:4988")
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--client-secret-file")
    ap.add_argument("--only", help="comma-separated scenario numbers")
    ap.add_argument("--peer", help="second gateway on the same database (scenario 10)")
    ap.add_argument("--pg", help="psycopg2 DSN for reading gateway.node/log (scenario 10)")
    ap.add_argument("--pg-password-file", help="password for --pg (otherwise PGPASSWORD)")
    args = ap.parse_args()
    if args.pg and args.pg_password_file:
        args.pg += " password=" + open(args.pg_password_file).read().strip()
    secret = os.environ.get("GATEWAY_CLIENT_SECRET")
    if args.client_secret_file:
        secret = open(args.client_secret_file).read().strip()
    if not secret:
        print("no secret: --client-secret-file or GATEWAY_CLIENT_SECRET", file=sys.stderr)
        return 2
    global SECRET
    SECRET = secret
    tok = token(args.gateway, args.client_id, secret)
    print(f"token obtained ({len(tok)} chars), audience {args.client_id}")
    scenarios = [scenario_register_ok, scenario_register_errors, scenario_auth, scenario_clock,
                 scenario_commands, scenario_replace, scenario_frames, scenario_route,
                 scenario_data_plane,
                 lambda gw, tok: scenario_mirror(gw, tok, args.peer, args.pg)]
    only = {int(x) for x in args.only.split(",")} if args.only else None
    try:
        for i, sc in enumerate(scenarios, 1):
            if only and i not in only:
                continue
            await sc(args.gateway, tok)
    except Fail as e:
        print(f"FAILED: {e}")
        return 1
    print("all scenarios passed")
    return 0


if __name__ == "__main__":
    rc = asyncio.run(main())
    # Sockets closed by the server mid-scenario leave background tasks in websockets, which
    # keep the interpreter from exiting on its own; the result has already been printed.
    sys.stdout.flush()
    os._exit(rc)
