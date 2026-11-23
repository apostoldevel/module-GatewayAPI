#!/usr/bin/env python3
"""Stub API module for self-testing GatewayAPI without a real module (README § Control plane,
§ Data plane, § Mirror). Plays the module side — handshake, frames, heartbeats, an HTTP echo
on the data plane — and checks the gateway in both directions: every refusal is provoked on
purpose.

Run (the gateway listens on 127.0.0.1:4988, audience from `module.GatewayAPI.audience`):

    python3 tests/stub_client.py --gateway http://127.0.0.1:4988 \
        --client-id service-example.com --client-secret-file /path/to/secret

The secret comes only from a file or the GATEWAY_CLIENT_SECRET variable, never passed via argv.
Exit 0 — all scenarios passed; otherwise the first FAILED one is printed and exit 1.

Scenario 10 (`gateway.node` mirror, README § Mirror) needs a SECOND gateway on the same
database (`--peer http://127.0.0.1:4989` — a second standalone process on a different port plays
the second worker) and database access (`--pg "host=127.0.0.1 port=5431 dbname=example
user=daemon"`, password via PGPASSWORD or `--pg-password-file`); skipped without them. Both
gateways run with `reload_interval` 5 — the scenario waits for the sweep and the reload after it.

Scenario 12 (a fresh worker) sends SIGHUP to the peer's master (`--peer-master-pid`): the master
spawns new workers and retires the old ones, and every request through the peer must be 200 or
503 + `Retry-After` — a fresh worker knows only its own sockets until its first reload, and a miss
then is not yet a 404. Scenario 13 (`--pg`) kills the listening connections and commits a row in
the same transaction: its NOTIFY is lost, and the row must appear on the reload the gateway runs
when LISTEN is confirmed again, well before `reload_interval`.
Scenario 11 (`--peer`, `--pg`) needs the two gateways to run under ONE pid — each in a PID namespace of
its own (a container each: `run11.sh` next to the stand's `run.sh`), with the network shared. With
different `NODE_NAME`s an instance registered on one of them must stay `ready` over three reloads, with
no `no socket on worker` in `gateway.log`; with the same `NODE_NAME` — or on a binary that identifies
a worker by its pid alone — the other one closes the live row every reload (the negative control).
With different pids it is skipped: nothing to collide.
Scenario 15 (`--peer`, `--pg`) sends commands through the peer to an instance whose socket this gateway holds:
they are relayed over NOTIFY `gateway_cmd`, signed with a key of the audience secret; forged, replayed and late
messages must not reach the module. With `--pg-container` it pauses the database's docker container for about ten
seconds: the relay must answer 503, and the command that reaches the channel after the database is back must not run.
Scenario 16 (`--peer`, `--pg` as a role that may signal the gateways' backends, `--pg-container`,
`--peer-master-pid`) cuts connections off with a statement in the server's hands (`pg_terminate_backend`;
`docker exec kill -STOP/-CONT` holds the pool's backends so the command is caught in flight): a relayed
`pg_notify` and a fresh worker's first reloads must be sent again (`PgRetry::if_lost`) — 200 from the module, not
503, and 503 `routes-loading`, not 404. Run on a gateway whose pool does not repeat them, both turn red.
Scenario 17 (`--peer`, `--peer-master-pid`) registers, right after each SIGHUP of the peer's master, a module
whose prefix nests in one this gateway holds: the fresh worker closes the /register `1013` without a CALLERROR
until its first reload and refuses it `409` after — never accepts it (T769). Scenario 18 (`--peer`, `--pg`,
`--pg-container`) pauses the database and registers two modules with overlapping prefixes, one on each gateway:
both are accepted, and after the reloads the one registered first (`gateway.node.registered`, ties by module)
keeps the prefix on both gateways while the other is closed `1008`. On a gateway that checks /register against
its own sockets only, or keeps "own sockets win" in the reload, both turn red.
Scenario 19 (`--peer`, `--pg` as a role allowed to `LOCK gateway.log IN SHARE MODE`) holds the journal
locked so that this gateway's `INSERT` of a new instance stays uncommitted, and registers the same instance on the
peer meanwhile (T1211): after the release the journal shows the first holder's `offline` and the peer's `ready`, and
the old socket is closed `1001` within 1.5 s. On a gateway whose registrations of one instance are not serialised the
peer turns `ready` into `ready` in silence — one journal row, the old socket open until the next reload — red.
Scenario 20 (`--v1-route`, a path the gateway lists in `v1_routes`) checks a path served as API v1 (README § API v1
routes): a /register whose prefix equals the path, or holds it, is refused 409; a prefix next to it is taken. Without a
token the path answers 401 problem+json with the bare challenge; with one, the answer and its status are those of the
`/api/v1` twin — a refusal as problem+json with the twin's `ERR-…` identifier. With the path left out of `v1_routes`
it turns red.

Gateway configuration for a run: `heartbeat_interval` 2 (scenario 4 waits for suspect/offline by
the clock), `allowed_cidr` with 127.0.0.0/8, `response_timeout_ms` 2000 (scenario 9 waits for a
504 after ~2s; at 30000 the echo itself drops the connection after 6s and the gateway correctly
answers 502).
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
import uuid

# The local gateway must never go through a proxy, whatever is set in the environment:
# requests honors HTTP_PROXY even for 127.0.0.1, and an external proxy answers with its own 403,
# which is easy to mistake for a gateway failure.
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

import collections  # noqa: E402
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
    # A close frame carries at most 123 bytes of reason (RFC 6455 §5.5): a longer one is a protocol error, and
    # the module would read a lost connection instead of the refusal (T769).
    ws2 = await connect(gw, tok, "other", "o1")
    await ws2.send(call("/register", register_payload("other", "o1", prefixes=["/api/v2/clients/" + "v" * 120])))
    r = await rx(ws2)
    cc, why = await close_code(ws2)
    check(r["t"] == 4 and r["c"] == 409 and cc == 1008 and len(why.encode()) <= 123,
          f"a reason longer than a close frame takes → 409 + close {cc}, reason cut to {len(why.encode())} bytes")

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

    # A malformed CALLERROR from the module: the HTTP caller still gets its answer.
    fut = loop.run_in_executor(None, lambda: requests.post(f"{gw}/gateway/clients/k1/ping", headers=hdr, timeout=8))
    while (m := await rx(ws, timeout=10))["t"] != 2:
        pass
    await ws.send(json.dumps({"t": 4, "u": m["u"], "c": "x", "m": 7}))
    r = await fut
    check(r.status_code == 502, f"CALLERROR with c/m of another type → HTTP {r.status_code}, socket lives")

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
    check(r.status_code == 404 and r.json()["type"] == "urn:apostol:gateway:unknown-instance",
          "command to a nonexistent instance → 404 unknown-instance")
    r = requests.post(f"{gw}/gateway/clients/k1/ping", headers=hdr, timeout=5)
    check(r.status_code == 404 and r.json()["type"] == "urn:apostol:gateway:unknown-instance",
          f"command to an offline instance → 404 unknown-instance ({r.json().get('detail')})")


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
    print("7. frames: binary → 1003, > 64 KiB → 1009, not JSON / wrong type / too deep → 400, repeated u → 400")
    ws = await connect(gw, tok, "clients", "f1")
    await register(ws, "clients", "f1")
    await ws.send("not json")
    r = await rx(ws)
    check(r["t"] == 4 and r["c"] == 400, "not JSON → 400")
    # Fields of another type and deep nesting: answered 400, the socket (and the worker under it) lives.
    for what, raw in [
        ("t a string", json.dumps({"t": "x", "u": "w1"})),
        ("t null", json.dumps({"t": None, "u": "w2"})),
        ("a a number", json.dumps({"t": 2, "u": "w3", "a": 5, "p": {}})),
        ("state a number", call("/status", {"state": 5}, u="w4")),
        ("nested 30000 deep", '{"t":2,"u":"w5","a":"/heartbeat","p":{"x":' + "[" * 30000 + "]" * 30000 + "}}"),
    ]:
        await ws.send(raw)
        r = await rx(ws)
        check(r["t"] == 4 and r["c"] == 400, f"{what} → 400 ({r.get('m')})")
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
        gw_worker = hdr(seen, "X-Gateway-Worker")
        check(len(gw_worker) == 1 and re.fullmatch(r"\S+:\d+", gw_worker[0]) is not None,
              f"X-Gateway-Worker: <node>:<pid> ({gw_worker})")
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
        r = q("SELECT state, worker, address, extract(epoch FROM now() - seen)::int, node FROM gateway.node WHERE module = %s AND instance = %s", module, instance)
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
    my_list = requests.get(f"{gw}/gateway/list", headers=hdrs, timeout=5).json()
    other_list = requests.get(f"{peer}/gateway/list", headers=hdrs, timeout=5).json()
    me, other = my_list["gateway_worker"], other_list["gateway_worker"]
    me_id, other_id = my_list["gateway_node"], other_list["gateway_node"]   # "<node>:<pid>"
    my_node = me_id.rsplit(":", 1)[0]
    check(me != other and me_id == f"{my_node}:{me}", f"two gateways — two workers ({me_id}, {other_id})")
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
        check(row("mirror", "m1")[1] == me and row("mirror", "m1")[4] == my_node,
              f"gateway.node.worker — my pid, gateway.node.node — my node ({row('mirror', 'm1')[4]!r})")
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
        check(hdr(echo.seen[-1], "X-Gateway-Worker") == [other_id], f"X-Gateway-Worker — the peer's identity ({hdr(echo.seen[-1], 'X-Gateway-Worker')})")
        # A command to the peer is relayed to my worker over gateway_cmd (scenario 15 has the details).
        fut = asyncio.ensure_future(asyncio.to_thread(requests.post, f"{peer}/gateway/mirror/m1/ping",
                                                      headers=hdrs, timeout=10))
        m = await rx(ws)
        await ws.send(json.dumps({"t": 3, "u": m["u"], "p": {"in_flight": 0}}))
        r = await fut
        check(m.get("a") == "/ping" and r.status_code == 200 and r.json() == {"in_flight": 0},
              f"command to peer → relayed to my worker, the module answered: HTTP {r.status_code}")

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
        check(row("mirror", "m2")[4] == other_id.rsplit(":", 1)[0], "gateway.node.node — the peer's node, set on the ON CONFLICT branch too")
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

        # 8. A row with MY identity (node and pid) but no socket (a previous life of it) → offline on
        #    reload. A row with my pid and NO node (a binary that writes none) is not mine: mirrored,
        #    never closed as "no socket on worker" — the same reload is the canary that it was read.
        l6 = last_log_id()
        q("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker, node)"
          " VALUES ('mirror', 'ghost', '0', '127.0.0.1:18198', ARRAY['/api/v2/mirror-ghost'], 'ready', 1, %s, %s)"
          " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', worker = EXCLUDED.worker, node = EXCLUDED.node, seen = now()",
          me, my_node)
        q("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker, node)"
          " VALUES ('mirror', 'ghost-null', '0', '127.0.0.1:18191', ARRAY['/api/v2/mirror-ghostnull'], 'ready', 1, %s, NULL)"
          " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', worker = EXCLUDED.worker, node = NULL, seen = now()", me)
        check(await settle(lambda: row("mirror", "ghost")[0] == "offline", RELOAD + 2, "ghost", hb=ws3), "row with my node and pid but no socket → offline on reload")
        j = journal("mirror", "ghost", l6)
        check(j and j[-1] == ("ready", "offline", "no socket on worker"), f"gateway.log: reason=no socket on worker ({j})")
        j = journal("mirror", "ghost-null", l6)
        check(row("mirror", "ghost-null")[0] == "ready" and not any(c == "no socket on worker" for _, _, c in j),
              f"row with my pid and node NULL — not mine: left ready by the same reload ({row('mirror', 'ghost-null')[0]}, {j})")
        gn = listing(gw, tok).get(("mirror", "ghost-null"), {})
        check(gn.get("source") == "mirror" and gn.get("state") == "ready" and gn.get("owner_node") is None and gn.get("owner_worker") == me,
              f"…mirrored on my side, owner_node null ({gn.get('source')}, {gn.get('state')}, {gn.get('owner_node')!r})")
        q("UPDATE gateway.node SET state = 'offline' WHERE module = 'mirror' AND instance = 'ghost-null'")

        # 9. Rows that did not come through /register get its checks (address inside allowed_cidr,
        #    valid prefixes): pg_notify is open to any role with CONNECT. A refused row changes
        #    nothing — no new mirror, no re-pointed address, no takeover of a live socket.
        def notify(**p):
            q("SELECT pg_notify('gateway', %s)", json.dumps(dict({"op": "UPDATE", "module": "mirror", "state": "ready", "state_from": "offline"}, **p)))

        notify(instance="forged", address="10.9.9.9:80", prefixes=["/api/v2/forged"], worker=424243)
        notify(instance="forged-p", address="127.0.0.1:18196", prefixes=["/api/v1/forged"], worker=424243)
        await asyncio.sleep(0.5)
        for side, name in ((gw, "mine"), (peer, "peer")):
            t = listing(side, tok)
            check(("mirror", "forged") not in t and ("mirror", "forged-p") not in t,
                  f"{name}: forged NOTIFY — address outside allowed_cidr, bad prefix — refused, no mirror")
        r = requests.get(f"{gw}/gateway/route", params={"path": "/api/v2/forged/x"}, headers=hdrs, timeout=5)
        check(r.status_code == 404, f"no route to the forged prefix ({r.status_code})")

        # the peer has m3 as a mirror, I hold its socket: a forged ready with a foreign pid and
        # a foreign address must neither re-point the peer nor take the instance over from me
        notify(instance="m3", address="10.9.9.9:80", prefixes=["/api/v2/mirror3"], worker=424243)
        await asyncio.sleep(0.5)
        check(listing(peer, tok)[("mirror", "m3")]["address"] == "127.0.0.1:18110", "peer: forged NOTIFY did not re-point m3")
        mine = listing(gw, tok)[("mirror", "m3")]
        check(mine["source"] == "socket" and mine["address"] == "127.0.0.1:18110", "mine: forged ready with a foreign pid is no takeover — socket kept")
        await ws3.send(call("/heartbeat", {"in_flight": 0}))
        check((await rx(ws3))["t"] == 3, "m3 socket alive after the forged NOTIFY")

        # the same forgery with the REAL address and prefix — every check of the payload passes. The
        # NOTIFY is only a signal: the row, read back, is still mine, so the socket stays.
        notify(instance="m3", address="127.0.0.1:18110", prefixes=["/api/v2/mirror3"], worker=424243, node="forged-node")
        await asyncio.sleep(HB / 2 + 0.3)   # the re-read lands; and the heartbeat below is not a 429 (< HB/2 since the last)
        mine = listing(gw, tok)[("mirror", "m3")]
        check(mine["source"] == "socket" and mine["owner_worker"] == me,
              f"mine: forged ready with the real address and another identity — no takeover, socket kept ({mine['source']}, {mine['owner_worker']})")
        await ws3.send(call("/heartbeat", {"in_flight": 0}))
        check((await rx(ws3))["t"] == 3, "m3 socket alive after the forged NOTIFY with the real address")
        # the peer's mirror of m3 may have taken the forged owner from the payload: routing is the same
        # address, and the peer's reload corrects the owner from the row

        # a prefix under another module's live prefix, from an address that IS allowed: the longest
        # prefix would win, so this is a hijack of /api/v2/mirror3/x/* — refused like a 409 at /register
        notify(module="evil", instance="e1", address="127.0.0.1:18194", prefixes=["/api/v2/mirror3/x"], worker=424243)
        notify(instance="bad\nname", address="127.0.0.1:18193", prefixes=["/api/v2/mirror-nl"], worker=424243)
        await asyncio.sleep(0.5)
        t = listing(gw, tok)
        check(("evil", "e1") not in t, "forged prefix under another module's live prefix — refused")
        check(not any("\n" in i for _, i in t), "forged name with a newline — refused")
        r = requests.get(f"{gw}/gateway/route", params={"path": "/api/v2/mirror3/x/1"}, headers=hdrs, timeout=5)
        check(r.status_code == 200 and r.json()["module"] == "mirror", f"/api/v2/mirror3/x/1 still routes to mirror/m3 ({r.status_code})")

        # my own row's address changed silently under my pid (no state change — no NOTIFY): the
        # peer would refuse it for good; the owner's reload re-asserts what its socket says
        q("UPDATE gateway.node SET address = '10.9.9.9:80' WHERE module = 'mirror' AND instance = 'm3'")
        check(await settle(lambda: row("mirror", "m3")[2] == "127.0.0.1:18110", RELOAD + 2, "m3 address", hb=ws3),
              "reload: my row's address changed under my pid → re-asserted from the socket")

        # reload: a row the database holds with an address outside allowed_cidr is not routed to;
        # a mirror whose row turns bad goes offline. The UPDATE of address alone is silent (no
        # state change — no NOTIFY), so only the reload can see it.
        q("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker)"
          " VALUES ('mirror', 'bad', '0', '10.9.9.9:80', ARRAY['/api/v2/mirror-bad'], 'ready', 1, NULL)"
          " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', address = EXCLUDED.address, worker = NULL, seen = now()")
        q("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker)"
          " VALUES ('mirror', 'turns', '0', '127.0.0.1:18195', ARRAY['/api/v2/mirror-turns'], 'ready', 1, NULL)"
          " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', address = EXCLUDED.address, worker = NULL, seen = now()")
        check(await settle(lambda: listing(gw, tok).get(("mirror", "turns"), {}).get("state") == "ready", 3, "turns"), "valid foreign row mirrored")
        q("UPDATE gateway.node SET address = '10.9.9.9:80', seen = now() WHERE module = 'mirror' AND instance = 'turns'")
        check(await settle(lambda: listing(gw, tok)[("mirror", "turns")]["state"] == "offline", RELOAD + 2, "turns off", hb=ws3),
              "reload: the mirror whose row turned bad → offline")
        check(row("mirror", "turns")[0] == "ready", "…by the refusal, not by the sweep: the database row is still ready")
        t = listing(gw, tok)
        check(("mirror", "bad") not in t and t[("mirror", "turns")]["address"] == "127.0.0.1:18195",
              "reload: bad row never mirrored, the refused one kept its last good address")
        q("UPDATE gateway.node SET state = 'offline' WHERE module = 'mirror' AND instance IN ('bad', 'turns')")

        # leaving rotation is taken even from a row that fails the checks: refusing a legitimate
        # offline would keep routing to the last good address until the next reload
        q("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker)"
          " VALUES ('mirror', 'leave', '0', '127.0.0.1:18192', ARRAY['/api/v2/mirror-leave'], 'ready', 1, NULL)"
          " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', address = EXCLUDED.address, worker = NULL, seen = now()")
        check(await settle(lambda: listing(gw, tok).get(("mirror", "leave"), {}).get("state") == "ready", 3, "leave"), "mirror/leave ready")
        q("UPDATE gateway.node SET state = 'offline', address = '10.9.9.9:80' WHERE module = 'mirror' AND instance = 'leave'")
        check(await settle(lambda: listing(gw, tok)[("mirror", "leave")]["state"] == "offline", 1.5, "leave off"),
              "offline carrying a refused address — taken within a NOTIFY, not a reload")
        check(listing(gw, tok)[("mirror", "leave")]["address"] == "127.0.0.1:18192", "…the state only: the address kept")

        # 10. Startup reload is covered indirectly: the peer started earlier and learned mirror/*
        #    via NOTIFY; rows inserted into the database BEFORE the worker started arrive on the
        #    first reload — visible as the line 'mirror: reload' in the new process's error.log
        #    (checked manually).
        await ws3.send(call("/unregister", {"reason": "done"}))
        await rx(ws3)
        await close_code(ws3)
    finally:
        await echo.stop()
        pg.close()


async def scenario_same_identity(gw, tok, peer, pg_dsn):
    print("11. one pid in two processes (PID namespaces): a worker is (node, pid) — with different nodes, three reloads without 'no socket on worker'")
    if not peer or not pg_dsn:
        print("  [skip] needs --peer and --pg")
        return
    hdrs = {"Authorization": f"Bearer {tok}"}
    a = requests.get(f"{gw}/gateway/list", headers=hdrs, timeout=5).json()
    b = requests.get(f"{peer}/gateway/list", headers=hdrs, timeout=5).json()
    # gateway_node is absent on a binary that identifies a worker by its pid alone
    print(f"  gateways: pid {a['gateway_worker']} node {a.get('gateway_node')} / pid {b['gateway_worker']} node {b.get('gateway_node')}")
    if a["gateway_worker"] != b["gateway_worker"]:
        print("  [skip] the gateways run under different pids — nothing collides (run them in PID namespaces of their own: run11.sh)")
        return
    check(True, f"precondition: both gateways run as pid {a['gateway_worker']}")
    import psycopg2
    pg = psycopg2.connect(pg_dsn)
    pg.autocommit = True

    def q(sql, *args):
        c = pg.cursor()
        c.execute(sql, args)
        return c.fetchall() if c.description else None

    def state():
        r = q("SELECT state FROM gateway.node WHERE module = 'twin' AND instance = 't1'")
        return r[0][0] if r else None

    ws = None
    try:
        q("UPDATE gateway.node SET state = 'offline' WHERE module = 'twin'")
        ws = await connect(gw, tok, "twin", "t1")
        check((await register(ws, "twin", "t1", address="127.0.0.1:18111", prefixes=["/api/v2/twin"]))["t"] == 3, "twin/t1 registered on the first gateway")
        t0 = time.time()
        while time.time() - t0 < 3 and not (state() == "ready" and listing(peer, tok).get(("twin", "t1"), {}).get("state") == "ready"):
            await asyncio.sleep(0.1)
        check(state() == "ready", "gateway.node: twin/t1 ready")
        check(listing(peer, tok).get(("twin", "t1"), {}).get("state") == "ready", "the second gateway mirrors it ready")
        since = q("SELECT coalesce(max(id), 0) FROM gateway.log")[0][0]

        window = 3 * RELOAD + 2     # three reloads of each gateway, and a tick
        samples, row_off, peer_off = 0, collections.Counter(), collections.Counter()
        next_hb = time.time() + HB
        end = time.time() + window
        while time.time() < end:
            if time.time() >= next_hb:
                await ws.send(call("/heartbeat", {"in_flight": 0}))
                await rx(ws)
                next_hb = time.time() + HB
            samples += 1
            st = state()
            if st != "ready":
                row_off[st] += 1
            ps = listing(peer, tok).get(("twin", "t1"), {}).get("state")
            if ps != "ready":
                peer_off[ps] += 1
            await asyncio.sleep(0.2)
        j = q("SELECT state_from, state_to, reason, worker, node FROM gateway.log"
              " WHERE module = 'twin' AND instance = 't1' AND id > %s ORDER BY id", since)
        nosock = sum(1 for r in j if r[2] == "no socket on worker")
        print(f"  {window} s, {samples} samples: gateway.node not ready {dict(row_off)}; the second gateway not ready {dict(peer_off)}")
        print(f"  gateway.log of twin/t1 in the window: {len(j)} transitions, {nosock} 'no socket on worker'")
        for r in j[:6]:
            print(f"    {r}")
        check(nosock == 0, f"no 'no socket on worker' over three reloads ({nosock})")
        check(not j, f"no transition of twin/t1 while it heartbeats ({len(j)})")
        check(not row_off and not peer_off, "ready at every sample, in the database and on the second gateway")
    finally:
        if ws is not None:
            try:
                await ws.send(call("/unregister", {"reason": "done"}))
                await rx(ws)
                await close_code(ws)
            except Exception:
                pass
        q("UPDATE gateway.node SET state = 'offline' WHERE module = 'twin'")
        pg.close()


async def scenario_fresh_worker(gw, tok, peer, peer_master):
    print("12. fresh worker (SIGHUP of the peer's master): another worker's instance is 503 until the first reload, never 404")
    if not peer or not peer_master:
        print("  [skip] needs --peer and --peer-master-pid")
        return
    import collections
    import signal

    def children():
        try:
            with open(f"/proc/{peer_master}/task/{peer_master}/children") as f:
                return set(f.read().split())
        except OSError:
            return set()

    hdrs = {"Authorization": f"Bearer {tok}"}
    echo = Echo(18120)
    await echo.start()
    ws = None
    try:
        ws = await connect(gw, tok, "fresh", "f1")
        check((await register(ws, "fresh", "f1", address="127.0.0.1:18120", prefixes=["/api/v2/fresh"]))["t"] == 3, "fresh/f1 registered on my side")
        deadline = time.time() + 3
        while time.time() < deadline and listing(peer, tok).get(("fresh", "f1"), {}).get("state") != "ready":
            await asyncio.sleep(0.1)
        check(listing(peer, tok).get(("fresh", "f1"), {}).get("state") == "ready", "peer: fresh/f1 ready via NOTIFY")
        seen = collections.Counter()
        details = collections.Counter()
        respawned = 0
        next_hb = time.time() + HB
        for _ in range(3):
            before = children()
            os.kill(peer_master, signal.SIGHUP)
            until = time.time() + 5     # longer than a fresh worker needs for its first reload
            while time.time() < until:
                if time.time() >= next_hb:
                    await ws.send(call("/heartbeat", {"in_flight": 0}))
                    await rx(ws)
                    next_hb = time.time() + HB
                try:
                    r = await asyncio.to_thread(requests.get, f"{peer}/api/v2/fresh/x", headers=hdrs, timeout=5)
                except requests.RequestException:
                    seen["dropped"] += 1   # a retiring worker closing an accepted connection — not the gateway's answer
                    continue
                seen[r.status_code] += 1
                if r.status_code != 200:
                    try:
                        detail = r.json().get("type", "").rsplit(":", 1)[-1] + ": " + str(r.json().get("detail"))
                    except ValueError:
                        detail = r.text[:60]
                    details[(r.status_code, r.headers.get("Retry-After"), detail)] += 1
            if children() - before:
                respawned += 1
        print(f"  statuses through the peer across 3 SIGHUPs: {dict(seen)}; non-200: {dict(details)}")
        check(respawned == 3, f"the peer's master spawned fresh workers on every SIGHUP ({respawned}/3)")
        check(seen[404] == 0, f"no 404 from a fresh worker ({seen[404]})")
        check(all(ra == "1" for (st, ra, _), n in details.items() if st == 503), "every 503 carries Retry-After: 1")
        # Contract edition 6, K7: "not loaded yet" has a slug of its own — a client branches on type, not on detail.
        check(seen[503] > 0 and all(d.startswith("routes-loading:") for (st, _, d), n in details.items() if st == 503),
              f"every 503 of a fresh worker is routes-loading, not no-instance ({seen[503]} of them)")
        check(seen[200] > 0, "the instance is served through the peer between the reloads")
    finally:
        if ws is not None:
            try:
                await ws.send(call("/unregister", {"reason": "done"}))
                await rx(ws)
                await close_code(ws)
            except Exception:
                pass
        await echo.stop()


async def scenario_listen_lost(gw, tok, pg_dsn):
    print("13. LISTEN lost: a row whose NOTIFY never reached the listener is found by the reload on re-LISTEN, not a reload_interval later")
    if not pg_dsn:
        print("  [skip] needs --pg")
        return
    import psycopg2
    pg = psycopg2.connect(pg_dsn)
    pg.autocommit = True
    names = []
    try:
        for n in range(3):
            name = f"lost{n}"
            names.append(name)
            c = pg.cursor()
            c.execute("BEGIN")
            # No NOTIFY at all where the role may do it (triggers off for this transaction): the
            # row can then reach the gateway only through a reload, and the listeners are killed
            # once it is committed (below), so the reload on re-LISTEN is bound to see it.
            # Otherwise the listeners are signalled in the same transaction — its NOTIFY goes to
            # backends on their way out, which a listener reconnecting within milliseconds can beat.
            c.execute("SAVEPOINT s")
            try:
                c.execute("SET LOCAL session_replication_role = replica")
                silent = True
            except psycopg2.Error:
                c.execute("ROLLBACK TO SAVEPOINT s")
                silent = False
            if not silent:
                c.execute("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity"
                          " WHERE datname = current_database() AND query ILIKE 'LISTEN%%' AND pid <> pg_backend_pid()")
                killed = c.fetchone()[0]
            c.execute("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker)"
                      " VALUES ('lost', %s, '0', %s, ARRAY[%s], 'ready', 1, NULL)"
                      " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', worker = NULL, seen = now()",
                      (name, f"127.0.0.1:{18180 + n}", f"/api/v2/{name}"))
            c.execute("COMMIT")
            if silent:
                # Killed only once the row is committed: killed inside the transaction, a listener
                # back within milliseconds re-reads before the COMMIT is visible (the WAL flush),
                # and a row with no NOTIFY committed after the re-LISTEN is a case only the
                # periodic reload covers — not the lost NOTIFY this scenario is about.
                c.execute("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity"
                          " WHERE datname = current_database() AND query ILIKE 'LISTEN%%' AND pid <> pg_backend_pid()")
                killed = c.fetchone()[0]
            check(killed >= 2, f"round {n + 1}: the listeners of both gateways killed ({killed}; NOTIFY {'suppressed' if silent else 'sent'})")
            t0 = time.time()
            while time.time() - t0 < RELOAD and listing(gw, tok).get(("lost", name), {}).get("state") != "ready":
                await asyncio.sleep(0.05)
            took = time.time() - t0
            check(listing(gw, tok).get(("lost", name), {}).get("state") == "ready" and took < RELOAD / 2,
                  f"round {n + 1}: row mirrored after {took:.2f} s (< {RELOAD / 2} s)")
            pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module = 'lost' AND instance = %s", (name,))
            await asyncio.sleep(1)
    finally:
        if names:
            pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module = 'lost' AND instance = ANY(%s)", (names,))
        pg.close()


async def scenario_prefix_handoff(gw, tok, pg_dsn):
    print("14. prefix handoff: a reload admits the new owner of a prefix whose old owner the same snapshot shows gone")
    if not pg_dsn:
        print("  [skip] needs --pg")
        return
    import psycopg2
    pg = psycopg2.connect(pg_dsn)
    pg.autocommit = True
    prefix = "/api/v2/handoff"
    upsert = ("INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker)"
              " VALUES (%s, %s, '0', %s, ARRAY[%s], 'ready', 1, NULL)"
              " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', worker = NULL, seen = now(),"
              " address = EXCLUDED.address, prefixes = EXCLUDED.prefixes")
    try:
        # The old owner, announced normally: every worker mirrors it.
        pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module IN ('hoa', 'hob', 'hoc', 'hod', 'hoe')")
        pg.cursor().execute(upsert, ("hob", "b1", "127.0.0.1:18190", prefix))
        t0 = time.time()
        while time.time() - t0 < RELOAD and listing(gw, tok).get(("hob", "b1"), {}).get("state") != "ready":
            await asyncio.sleep(0.05)
        check(listing(gw, tok).get(("hob", "b1"), {}).get("state") == "ready", "old owner hob/b1 mirrored")

        # The handoff with both NOTIFYs lost: old owner offline, new owner ready — seen only by a reload.
        c = pg.cursor()
        c.execute("BEGIN")
        try:
            c.execute("SET LOCAL session_replication_role = replica")
        except psycopg2.Error:
            c.execute("ROLLBACK")
            print("  [skip] needs a role that may set session_replication_role")
            return
        c.execute("UPDATE gateway.node SET state = 'offline' WHERE module = 'hob'")
        c.execute(upsert, ("hoa", "a1", "127.0.0.1:18191", prefix))
        c.execute("COMMIT")
        # A reload now: re-LISTEN re-reads at once (3b), no waiting for reload_interval.
        c.execute("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity"
                  " WHERE datname = current_database() AND query ILIKE 'LISTEN%%' AND pid <> pg_backend_pid()")
        killed = c.fetchone()[0]
        check(killed >= 1, f"listeners killed ({killed}) — a reload follows")
        t0 = time.time()
        while time.time() - t0 < RELOAD and listing(gw, tok).get(("hoa", "a1"), {}).get("state") != "ready":
            await asyncio.sleep(0.05)
        took = time.time() - t0
        rows = listing(gw, tok)
        check(rows.get(("hoa", "a1"), {}).get("state") == "ready" and took < RELOAD / 2,
              f"new owner hoa/a1 ready after {took:.2f} s (< {RELOAD / 2} s) — not refused against the stale hob/b1")
        check(rows.get(("hob", "b1"), {}).get("state") == "offline", "old owner hob/b1 offline")

        async def silent_then_reload(rows_, canary):
            # rows_ written with no NOTIFY, plus a canary row only a reload can bring; returns once
            # the canary is mirrored — i.e. a reload has run over this snapshot.
            c.execute("BEGIN")
            c.execute("SET LOCAL session_replication_role = replica")
            for r in rows_:
                c.execute(upsert, r)
            c.execute(upsert, ("hod", canary, "127.0.0.1:18199", f"/api/v2/{canary}"))
            c.execute("COMMIT")
            c.execute("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity"
                      " WHERE datname = current_database() AND query ILIKE 'LISTEN%%' AND pid <> pg_backend_pid()")
            n = c.fetchone()[0]
            check(n >= 1, f"listeners killed ({n}) — a reload follows")
            t = time.time()
            while time.time() - t < RELOAD and listing(gw, tok).get(("hod", canary), {}).get("state") != "ready":
                await asyncio.sleep(0.05)
            took_ = time.time() - t
            check(listing(gw, tok).get(("hod", canary), {}).get("state") == "ready" and took_ < RELOAD / 2,
                  f"canary hod/{canary} mirrored after {took_:.2f} s — the reload ran")
            return listing(gw, tok)

        # The other way round: a newcomer under the prefix of an established owner. The newcomer is
        # refused; the established owner must not be refused against it.
        rows = await silent_then_reload([("hoc", "c1", "127.0.0.1:18192", prefix + "/x")], "d1")
        check(rows.get(("hoc", "c1"), {}).get("state") != "ready", "newcomer hoc/c1 under hoa's prefix — refused")
        check(rows.get(("hoa", "a1"), {}).get("state") == "ready", "established hoa/a1 stays ready")

        # An established owner moves to another prefix and a newcomer takes its old one, both in one
        # snapshot: the old prefix is no longer held — the newcomer is admitted by this very reload.
        pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module = 'hoc'")
        rows = await silent_then_reload([("hoa", "a1", "127.0.0.1:18191", prefix + "2"),
                                          ("hoe", "e1", "127.0.0.1:18193", prefix)], "d2")
        check(rows.get(("hoe", "e1"), {}).get("state") == "ready",
              "newcomer hoe/e1 on the prefix hoa/a1 just left — admitted by the same reload")
        check(rows.get(("hoa", "a1"), {}).get("state") == "ready", "hoa/a1 ready on its new prefix")
    finally:
        pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module IN ('hoa', 'hob', 'hoc', 'hod', 'hoe')")
        pg.close()


def cmd_signed(body):
    """The gateway_cmd wire form, signed the way a gateway worker signs it (README § Commands across workers)."""
    import hashlib
    import hmac
    key = hmac.new(SECRET.encode(), b"apostol:gateway_cmd", hashlib.sha256).hexdigest()
    text = json.dumps(body, separators=(",", ":"))
    return hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest() + "." + text


async def scenario_commands_relayed(gw, tok, peer, pg_dsn, pg_container):
    print("15. commands across workers: a command sent to a worker without the socket is relayed over gateway_cmd")
    if not peer or not pg_dsn:
        print("  [skip] needs --peer and --pg")
        return
    import subprocess
    import psycopg2
    hdr = {"Authorization": f"Bearer {tok}"}
    loop = asyncio.get_event_loop()
    pg = psycopg2.connect(pg_dsn)
    pg.autocommit = True
    spy = psycopg2.connect(pg_dsn)   # sees every payload on the channel, as any role with CONNECT can
    spy.autocommit = True
    spy.cursor().execute("LISTEN gateway_cmd")

    def post(base, path, timeout=12, **kw):
        return loop.run_in_executor(None, lambda: requests.post(f"{base}/gateway/{path}", headers=hdr,
                                                                timeout=timeout, **kw))

    def captured():
        spy.poll()
        out = [n.payload for n in spy.notifies]
        spy.notifies.clear()
        return out

    def notify(payload):
        pg.cursor().execute("SELECT pg_notify('gateway_cmd', %s)", (payload,))

    ws = await connect(gw, tok, "relay", "x1")
    await register(ws, "relay", "x1")

    async def beat():
        # The scenario runs longer than offline_after heartbeats; the answers are skipped by the readers.
        while True:
            await asyncio.sleep(HB)
            await ws.send(call("/heartbeat", {"in_flight": 0}))

    async def next_call(timeout):
        end = time.monotonic() + timeout
        while True:
            m = await rx(ws, timeout=max(0.01, end - time.monotonic()))
            if m.get("t") == 2:
                return m

    beater = asyncio.ensure_future(beat())
    try:
        t0 = time.time()
        while time.time() - t0 < RELOAD and listing(peer, tok).get(("relay", "x1"), {}).get("state") != "ready":
            await asyncio.sleep(0.05)
        check(listing(peer, tok).get(("relay", "x1"), {}).get("state") == "ready", "relay/x1 on this gateway, mirrored by the peer")

        async def calls(within):
            """CALLs the module gets within `within` s, each answered: /ping {in_flight: 7}, /reload CALLERROR."""
            got = []
            end = time.monotonic() + within
            while (left := end - time.monotonic()) > 0:
                try:
                    m = await rx(ws, timeout=left)
                except asyncio.TimeoutError:
                    break
                if m.get("t") != 2:
                    continue
                got.append(m["a"])
                if m["a"] == "/reload":
                    await ws.send(json.dumps({"t": 4, "u": m["u"], "c": 500, "m": "cannot reload"}))
                else:
                    await ws.send(json.dumps({"t": 3, "u": m["u"], "p": {"in_flight": 7}}))
            return got

        captured()
        fut = post(peer, "relay/x1/ping")
        got = await calls(2)
        r = await fut
        check(got == ["/ping"] and r.status_code == 200 and r.json() == {"in_flight": 7},
              f"POST peer …/ping → relayed to the socket's worker, module answered once: HTTP {r.status_code} {r.text}")
        wire = captured()
        cmd = [w for w in wire if '"k":"cmd"' in w]
        check(len(cmd) == 1 and len(wire) == 2 and all(len(w) > 65 and w[64] == "." for w in wire),
              f"the channel carried one signed command and one signed answer ({len(wire)} payloads)")

        # A genuine command replayed at once, well within its deadline: only its id stops it.
        fut = post(peer, "relay/x1/ping")
        first = await next_call(3)
        spy.poll()
        t0 = time.monotonic()
        while not [n for n in spy.notifies if '"k":"cmd"' in n.payload]:
            check(time.monotonic() - t0 < 2, "the relayed command seen on the channel")
            await asyncio.sleep(0.02)
            spy.poll()
        notify([n.payload for n in spy.notifies if '"k":"cmd"' in n.payload][0])
        await ws.send(json.dumps({"t": 3, "u": first["u"], "p": {"in_flight": 7}}))
        r = await fut
        got = await calls(1.5)
        check(r.status_code == 200 and got == [],
              "genuine command replayed within its deadline → the module got it once (the id is spent)")
        captured()

        fut = post(peer, "relay/x1/reload")
        got = await calls(2)
        r = await fut
        check(got == ["/reload"] and r.status_code == 502 and r.json()["type"] == "urn:apostol:gateway:upstream-error",
              f"module CALLERROR through the relay → 502 ({r.json().get('detail')})")

        t0 = time.monotonic()
        fut = post(peer, "relay/x1/ping", json={"x": 1})
        m = await next_call(3)   # received, never answered
        r = await fut
        took = time.monotonic() - t0
        check(m["a"] == "/ping" and r.status_code == 504 and 4 <= took <= 9,
              f"module silent → 504 through the relay after {took:.1f} s ({r.json().get('detail')})")

        # Forgeries — none may reach the module. A correctly signed twin follows them, so "no CALL" is not
        # the module being deaf.
        replay = cmd[0]
        forged = [
            ("unsigned", json.dumps({"k": "cmd", "id": str(uuid.uuid4()), "module": "relay", "instance": "x1",
                                     "command": "drain", "p": {}, "deadline": int(time.time() * 1000) + 2000})),
            ("wrong key", "0" * 64 + "." + json.dumps({"k": "cmd", "id": str(uuid.uuid4()), "module": "relay",
                                                         "instance": "x1", "command": "drain", "p": {},
                                                         "deadline": int(time.time() * 1000) + 2000})),
            ("genuine, replayed after its deadline", replay),
            ("signed, past its deadline", cmd_signed({"k": "cmd", "id": str(uuid.uuid4()), "from": 1, "module": "relay",
                                                      "instance": "x1", "command": "drain", "p": {},
                                                      "deadline": int(time.time() * 1000) - 1})),
            ("signed, body altered", cmd_signed({"k": "cmd", "id": str(uuid.uuid4()), "from": 1, "module": "relay",
                                                 "instance": "x1", "command": "ping", "p": {},
                                                 "deadline": int(time.time() * 1000) + 2000}).replace('"ping"', '"drain"')),
        ]
        for what, payload in forged:
            notify(payload)
            got = await calls(1.5)
            check(got == [], f"forged gateway_cmd ({what}) → no CALL reached the module")
        captured()
        notify(cmd_signed({"k": "cmd", "id": str(uuid.uuid4()), "from": "stub:1", "module": "relay", "instance": "x1",
                           "command": "ping", "p": {}, "deadline": int(time.time() * 1000) + 2000}))
        got = await calls(1.5)
        check(got == ["/ping"], "positive control: the same command signed with the audience key → the CALL arrives")

        # A row every worker mirrors as ready, with no socket behind it anywhere: relayed, answered by nobody.
        pg.cursor().execute(
            "INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker)"
            " VALUES ('relay', 'ghost', '0', '127.0.0.1:18195', ARRAY['/api/v2/relayghost'], 'ready', 1, NULL)"
            " ON CONFLICT (module, instance) DO UPDATE SET state = 'ready', worker = NULL, seen = now()")
        t0 = time.time()
        while time.time() - t0 < RELOAD and listing(peer, tok).get(("relay", "ghost"), {}).get("state") != "ready":
            await asyncio.sleep(0.05)
        t0 = time.monotonic()
        r = await post(peer, "relay/ghost/ping", timeout=15)   # not blocking: the heartbeats must go on
        took = time.monotonic() - t0
        check(r.status_code == 504 and "no worker holding the socket" in r.json().get("detail", "") and 9 <= took <= 11,
              f"ready row with no socket anywhere → 504 by the relaying worker after {took:.1f} s")

        r = await post(peer, "relay/nobody/ping", timeout=5)
        check(r.status_code == 404 and r.json()["type"] == "urn:apostol:gateway:unknown-instance",
              "unknown instance through the peer → 404 unknown-instance, nothing relayed")

        if pg_container:
            # The database away: pg_notify waits in the pool's queue with no error — 503 by its age. After the
            # database is back, the queued command reaches the channel past its deadline and must not run.
            subprocess.run(["docker", "pause", pg_container], check=True, capture_output=True)
            try:
                t0 = time.monotonic()
                r = await post(peer, "relay/x1/ping")
                took = time.monotonic() - t0
            finally:
                subprocess.run(["docker", "unpause", pg_container], check=True, capture_output=True)
            check(r.status_code == 503 and r.json()["type"] == "urn:apostol:gateway:database-unavailable"
                  and r.headers.get("Retry-After") == "1" and 9 <= took <= 11,
                  f"database paused → 503 database-unavailable + Retry-After after {took:.1f} s ({r.json().get('detail')})")
            got = await calls(3)
            check(got == [], "the command queued while the database was away reached the channel late — not run")
        else:
            print("  [skip] database away: needs --pg-container")

        fut = post(peer, "relay/x1/drain", json={"reason": "relay test"})
        m = await next_call(3)
        await ws.send(json.dumps({"t": 3, "u": m["u"], "p": {}}))
        r = await fut
        check(m["a"] == "/drain" and m["p"] == {"reason": "relay test"} and r.status_code == 200,
              f"/drain through the peer → the body reached the module, HTTP {r.status_code}")
    finally:
        beater.cancel()
        await ws.close()
        pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module = 'relay'")
        pg.close()
        spy.close()


async def scenario_statement_lost(gw, tok, peer, pg_dsn, pg_container, peer_master):
    print("16. connection lost with the statement in the server's hands: the pool sends it again (PgRetry::if_lost, T768)")
    if not peer or not pg_dsn or not pg_container or not peer_master:
        print("  [skip] needs --peer, --pg, --pg-container and --peer-master-pid")
        return
    import collections
    import signal
    import subprocess
    import psycopg2
    hdrs = {"Authorization": f"Bearer {tok}"}
    loop = asyncio.get_event_loop()
    pg = psycopg2.connect(pg_dsn)
    pg.autocommit = True

    def in_container(*cmd):
        # Through sh: its builtin kill, the image need not carry procps.
        subprocess.run(["docker", "exec", pg_container, "sh", "-c", " ".join(cmd)], check=True, capture_output=True)

    def pool_backends():
        # Every pool connection of the gateways, listeners excepted: a client port seen through
        # docker-proxy names no process, so all of them are taken — what this checks does not
        # depend on whose they are.
        c = pg.cursor()
        c.execute("SELECT pid FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()"
                  " AND usename = (SELECT usename FROM pg_stat_activity WHERE query ILIKE 'LISTEN%%' LIMIT 1)"
                  " AND query NOT ILIKE 'LISTEN%%' AND backend_type = 'client backend'")
        return [str(r[0]) for r in c.fetchall()]

    def children():
        try:
            with open(f"/proc/{peer_master}/task/{peer_master}/children") as f:
                return set(f.read().split())
        except OSError:
            return set()

    def is_worker(pid):
        # The master respawns its helper too; only a worker reloads the routing table.
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                return b"worker" in f.read()
        except OSError:
            return False

    ws = await connect(gw, tok, "lost16", "l1")
    echo = Echo(18160)
    await echo.start()
    next_hb = time.time() + HB

    async def keep_alive():
        nonlocal next_hb
        if time.time() >= next_hb:
            await ws.send(call("/heartbeat", {"in_flight": 0}))
            next_hb = time.time() + HB

    try:
        check((await register(ws, "lost16", "l1", address="127.0.0.1:18160", prefixes=["/api/v2/lost16"]))["t"] == 3,
              "lost16/l1 registered on this gateway")
        t0 = time.time()
        while time.time() - t0 < RELOAD and listing(peer, tok).get(("lost16", "l1"), {}).get("state") != "ready":
            await asyncio.sleep(0.05)
        check(listing(peer, tok).get(("lost16", "l1"), {}).get("state") == "ready", "lost16/l1 mirrored by the peer")

        # (a) A relayed command whose pg_notify is cut off in the server's hands. The pool connections
        # are stopped, the command goes out through the peer into one of them, and the backends are
        # then terminated: the statement was sent whole, and the connection is lost before an answer.
        # Sent again (if_lost), it reaches the holder and the module answers: 200. Reported instead
        # (PgRetry::never), the peer answers 503 "the database refused the command" at once.
        stopped = pool_backends()
        in_container("kill", "-STOP", *stopped)
        sent = time.monotonic()
        try:
            fut = loop.run_in_executor(None, lambda: requests.post(f"{peer}/gateway/lost16/l1/ping", headers=hdrs, timeout=12))
            await asyncio.sleep(0.5)
            pg.cursor().execute("SELECT count(pg_terminate_backend(p::int)) FROM unnest(%s::text[]) p", (stopped,))
        finally:
            in_container("kill", "-CONT", *stopped)
        answered = None
        end = time.monotonic() + 10
        while not fut.done() and time.monotonic() < end:
            try:
                m = await rx(ws, timeout=0.2)
            except asyncio.TimeoutError:
                continue
            if m.get("t") == 2 and m.get("a") == "/ping":
                answered = m["a"]
                await ws.send(json.dumps({"t": 3, "u": m["u"], "p": {"in_flight": 16}}))
        r = await fut
        took = time.monotonic() - sent
        # Not before the backends were let go: an answer sooner went out on a connection
        # pool_backends() missed, and nothing was cut off.
        check(took >= 0.5, f"the command was caught in flight: answered after {took:.2f} s, not before the backends were let go")
        check(r.status_code == 200 and answered == "/ping",
              f"pg_notify lost with the connection ({len(stopped)} backends): sent again, the module answered — HTTP {r.status_code} {r.text[:120]}")

        # (b) A fresh worker whose first reloads are cut off. The table is locked, so every reload
        # waits in the server; the fresh worker's is terminated three times. Sent again (if_lost),
        # the worker keeps answering 503 routes-loading and serves once the lock is gone. Counted as
        # failed reloads instead, the third sets "loaded" without a table and a legal path is 404.
        lock = psycopg2.connect(pg_dsn)
        lc = lock.cursor()
        seen = collections.Counter()
        kills = collections.Counter()   # per fresh pid: with several workers, 3 in all would be fewer than 3 each
        try:
            lc.execute("BEGIN")
            lc.execute("LOCK TABLE gateway.node IN EXCLUSIVE MODE")
            before = children()
            os.kill(peer_master, signal.SIGHUP)
            fresh = set()
            end = time.time() + 15
            while time.time() < end and not (fresh and all(kills[p] >= 3 for p in fresh)):
                await keep_alive()
                fresh = fresh or {p for p in children() - before if is_worker(p)}
                if fresh:
                    for p in fresh:
                        c = pg.cursor()
                        c.execute("SELECT pid FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE %s",
                                  (f"%swept by worker %:{p}: seen older%",))
                        for (pid,) in c.fetchall():
                            pg.cursor().execute("SELECT pg_terminate_backend(%s)", (pid,))
                            kills[p] += 1
                try:
                    rr = await asyncio.to_thread(requests.get, f"{peer}/api/v2/lost16/x", headers=hdrs, timeout=5)
                    seen[(rr.status_code, rr.json().get("type", "").rsplit(":", 1)[-1] if rr.status_code != 200 else "")] += 1
                except (requests.RequestException, ValueError):
                    seen["dropped"] += 1
                await asyncio.sleep(0.1)
            t1 = time.time()
            while time.time() - t1 < 1.5:
                await keep_alive()
                try:
                    rr = await asyncio.to_thread(requests.get, f"{peer}/api/v2/lost16/x", headers=hdrs, timeout=5)
                    seen[(rr.status_code, rr.json().get("type", "").rsplit(":", 1)[-1] if rr.status_code != 200 else "")] += 1
                except (requests.RequestException, ValueError):
                    seen["dropped"] += 1
                await asyncio.sleep(0.1)
        finally:
            lock.rollback()
            lock.close()
        served = False
        t2 = time.time()
        while time.time() - t2 < 5 and not served:
            await keep_alive()
            rr = await asyncio.to_thread(requests.get, f"{peer}/api/v2/lost16/x", headers=hdrs, timeout=5)
            served = rr.status_code == 200
            await asyncio.sleep(0.1)
        print(f"  statuses through the peer while its fresh worker's reloads were cut off: {dict(seen)}")
        check(fresh and all(kills[p] >= 3 for p in fresh),
              f"every fresh worker's reload cut off in the server's hands 3 times or more ({dict(kills)})")
        check(not [k for k in seen if k != "dropped" and k[0] == 404], "no 404 from the fresh worker while its reloads were lost")
        check(all(k[1] == "routes-loading" for k in seen if k != "dropped" and k[0] == 503) and
              any(k != "dropped" and k[0] == 503 for k in seen), "every 503 meanwhile is routes-loading")
        check(served, f"served through the peer once the lock is gone (HTTP {rr.status_code})")
    finally:
        try:
            await ws.send(call("/unregister", {"reason": "done"}))
            await close_code(ws)
        except Exception:
            pass
        await echo.stop()
        pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module = 'lost16'")
        pg.close()


class Holder:
    """A registered socket kept alive by heartbeats; `closed` is (code, reason) once the gateway ends it."""
    def __init__(self, ws):
        self.ws, self.closed = ws, None
        self.task = asyncio.create_task(self._run())

    async def _run(self):
        try:
            while True:
                await self.ws.send(call("/heartbeat", {"in_flight": 0}))
                until = time.monotonic() + HB
                while time.monotonic() < until:   # answers and the gateway's CALLs
                    try:
                        m = json.loads(await asyncio.wait_for(self.ws.recv(), until - time.monotonic()))
                    except asyncio.TimeoutError:
                        break
                    if m.get("t") == 2:
                        await self.ws.send(json.dumps({"t": 3, "u": m["u"], "p": {}}))
        except websockets.ConnectionClosed as e:
            self.closed = (e.rcvd.code if e.rcvd else None, e.rcvd.reason if e.rcvd else "")

    async def stop(self):
        self.task.cancel()
        if self.closed is None:
            try:
                await self.ws.send(call("/unregister", {"reason": "done"}))
                await close_code(self.ws, 2)
            except Exception:
                pass


async def register_outcome(gw, tok, module, instance, **over):
    """("result", ws) | ("error", code, message, close code) | ("closed", code, reason) — the last with no frame."""
    ws = await connect(gw, tok, module, instance)
    await ws.send(call("/register", register_payload(module, instance, **over)))
    try:
        m = await rx(ws)
    except websockets.ConnectionClosed as e:
        return ("closed", e.rcvd.code if e.rcvd else None, e.rcvd.reason if e.rcvd else "")
    if m["t"] == 3:
        return ("result", ws)
    code, _ = await close_code(ws)
    return ("error", m.get("c"), m.get("m"), code)


def route_of(gw, tok, path):
    r = route(gw, tok, path)
    return r.json()["module"] if r.status_code == 200 else r.status_code


async def scenario_register_before_load(gw, tok, peer, peer_master):
    print("17. /register on a fresh worker before its first reload: close 1013, no CALLERROR; the 409 comes on the retry (T769)")
    if not peer or not peer_master:
        print("  [skip] needs --peer and --peer-master-pid")
        return
    import signal

    def children():
        try:
            with open(f"/proc/{peer_master}/task/{peer_master}/children") as f:
                return set(f.read().split())
        except OSError:
            return set()

    holder = None
    try:
        r = await register_outcome(gw, tok, "own17", "o1", prefixes=["/api/v2/own17"])
        check(r[0] == "result", "own17/o1 registered on my side")
        holder = Holder(r[1])
        deadline = time.time() + 3
        while time.time() < deadline and listing(peer, tok).get(("own17", "o1"), {}).get("state") != "ready":
            await asyncio.sleep(0.1)
        check(listing(peer, tok).get(("own17", "o1"), {}).get("state") == "ready", "peer: own17/o1 ready via NOTIFY")
        seen = collections.Counter()
        for _ in range(3):
            before = children()
            os.kill(peer_master, signal.SIGHUP)
            until = time.time() + 3
            while time.time() < until and not (children() - before):
                await asyncio.sleep(0.01)
            # Another module claims a prefix nested in own17's, at once and for the next two seconds:
            # the fresh worker refuses it 1013 until its table is loaded, 409 after; never accepts it.
            until = time.time() + 2
            while time.time() < until:
                try:
                    o = await register_outcome(peer, tok, "cross17", "c1", prefixes=["/api/v2/own17/sub"])
                except (OSError, websockets.InvalidHandshake, asyncio.TimeoutError):
                    seen["dropped"] += 1   # a retiring worker closing an accepted connection
                    continue
                if o[0] == "result":
                    seen["accepted"] += 1
                    await o[1].close()
                elif o[0] == "closed":
                    seen[f"close {o[1]} {o[2]}"] += 1
                else:
                    seen[f"{o[1]} + close {o[3]}"] += 1
                await asyncio.sleep(0.02)
        print(f"  outcomes on the peer across 3 SIGHUPs: {dict(seen)}")
        check(seen["accepted"] == 0, "the nested prefix of another module was never accepted")
        check(seen["close 1013 routing table loading"] > 0, "a fresh worker closed the /register 1013 before its first reload")
        check(seen["409 + close 1008"] > 0 and
              set(seen) <= {"close 1013 routing table loading", "409 + close 1008", "dropped"},
              "every other outcome is CALLERROR 409 and close 1008")
        check(route_of(peer, tok, "/api/v2/own17/sub/x") == "own17" and route_of(peer, tok, "/api/v2/own17/x") == "own17",
              "the peer routes both paths to own17")
        check(holder.closed is None, "own17's socket is alive")
    finally:
        if holder:
            await holder.stop()


async def scenario_register_race(gw, tok, peer, pg_dsn, pg_container):
    print("18. two modules register overlapping prefixes on two workers at once: the earlier registration keeps "
          "the prefix on both, the later one is closed 1008 (T769)")
    if not peer or not pg_dsn or not pg_container:
        print("  [skip] needs --peer, --pg and --pg-container")
        return
    import psycopg2
    import subprocess
    pg = psycopg2.connect(pg_dsn)
    pg.autocommit = True
    held = {}
    try:
        pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module IN ('race18a', 'race18b')")
        # The database paused: neither upsert commits, neither NOTIFY travels — each worker sees only its own socket.
        subprocess.run(["docker", "pause", pg_container], check=True, capture_output=True)
        try:
            ra, rb = await asyncio.gather(
                register_outcome(gw, tok, "race18a", "a1", prefixes=["/api/v2/race18"]),
                register_outcome(peer, tok, "race18b", "b1", prefixes=["/api/v2/race18/sub"]))
        finally:
            subprocess.run(["docker", "unpause", pg_container], check=True, capture_output=True)
        check(ra[0] == "result" and rb[0] == "result", "both registrations accepted while the workers could not know of each other")
        held = {"race18a": Holder(ra[1]), "race18b": Holder(rb[1])}
        await asyncio.sleep(1)
        cur = pg.cursor()
        # No state filter: the loser's worker may have reloaded and written it offline already; `registered` stays.
        cur.execute("SELECT module FROM gateway.node WHERE module IN ('race18a', 'race18b')"
                    " ORDER BY registered, module")
        order = [m for (m,) in cur.fetchall()]
        check(len(order) == 2, f"both rows in gateway.node ({order})")
        winner, loser = order
        print(f"  registered first: {winner}")
        t0 = time.time()
        while time.time() - t0 < 2 * RELOAD + 3 and held[loser].closed is None:
            await asyncio.sleep(0.2)
        check(held[loser].closed is not None and held[loser].closed[0] == 1008 and
              held[loser].closed[1].endswith(f"belongs to module {winner}"),
              f"{loser} closed by its worker's reload: {held[loser].closed}")
        check(held[winner].closed is None, f"{winner}'s socket is alive")
        await asyncio.sleep(RELOAD + 1)   # the other worker's reload too
        for name, g in (("mine", gw), ("peer", peer)):
            got = {p: route_of(g, tok, p) for p in ("/api/v2/race18/x", "/api/v2/race18/sub/x")}
            print(f"  {name}: {got}")
            check(loser not in got.values(), f"{name}: no path goes to {loser}")
            check(got["/api/v2/race18/sub/x"] == winner, f"{name}: the overlapping path goes to {winner}")
        cur.execute("SELECT state FROM gateway.node WHERE module = %s", (loser,))
        check(cur.fetchone()[0] == "offline", f"{loser}'s row offline")
    finally:
        for h in held.values():
            await h.stop()
        pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module IN ('race18a', 'race18b')")
        pg.close()


async def scenario_takeover_uncommitted(gw, tok, peer, pg_dsn):
    print("19. the same instance registers on the peer while this gateway's INSERT of it is not committed yet: "
          "the takeover is journalled and this gateway closes the old socket 1001 at once, not at its next reload (T1211)")
    if not peer or not pg_dsn:
        print("  [skip] needs --peer and --pg")
        return
    import psycopg2
    import psycopg2.errors
    module, instance = f"take19{int(time.time() * 1000) % 1000000}", "t1"
    pg = psycopg2.connect(pg_dsn)
    pg.autocommit = True
    hold = psycopg2.connect(pg_dsn)          # holds the trigger of the first upsert: its INSERT stays uncommitted
    old = new = None
    try:
        cur = hold.cursor()
        try:
            cur.execute("LOCK TABLE gateway.log IN SHARE MODE")
        except psycopg2.errors.InsufficientPrivilege:
            hold.rollback()
            print("  [skip] the --pg role may not LOCK gateway.log IN SHARE MODE")
            return

        def waiting():
            c = pg.cursor()
            c.execute("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'"
                      " AND query LIKE %s", (f"%gateway.node%{module}%",))
            return c.fetchone()[0]

        async def until_waiting(n):
            t0 = time.time()
            while waiting() < n and time.time() - t0 < 5:
                await asyncio.sleep(0.05)
            return waiting()

        ra = await register_outcome(gw, tok, module, instance)
        check(ra[0] == "result", f"registered on this gateway: {ra[0]}")
        old = Holder(ra[1])
        check(await until_waiting(1) >= 1, "this gateway's upsert is held inside its transaction")
        # The module reconnects to the peer: the peer has heard nothing of the first registration.
        rb = await register_outcome(peer, tok, module, instance)
        check(rb[0] == "result", f"registered on the peer: {rb[0]}")
        new = Holder(rb[1])
        check(await until_waiting(2) >= 2, "the peer's upsert waits for the first one")
        t_release = time.time()
        hold.commit()                        # the first upsert commits, the peer's follows it
        while time.time() - t_release < 3 and old.closed is None:
            await asyncio.sleep(0.05)
        closed_after = time.time() - t_release
        c = pg.cursor()
        c.execute("SELECT node, worker, state FROM gateway.node WHERE module = %s AND instance = %s", (module, instance))
        row = c.fetchone()
        c.execute("SELECT coalesce(state_from, '(none)'), state_to, node, reason FROM gateway.log"
                  " WHERE module = %s AND instance = %s ORDER BY id", (module, instance))
        log = c.fetchall()
        print(f"  row {row}; log {log}; old socket {old.closed} after {closed_after:.2f} s")
        check(row is not None and row[2] == "ready", f"the row is ready: {row}")
        # The journal is the deterministic half: the takeover is an offline of the first holder and a ready of the
        # second. Without it the peer's upsert turned ready into ready — no transition, no NOTIFY — and this gateway
        # heard of the takeover only by its next reload (up to reload_interval later).
        check(len(log) == 3 and log[1][:2] == ("ready", "offline") and log[2][:2] == ("offline", "ready")
              and log[1][2] != log[2][2], f"takeover journalled as offline + ready of the new holder: {log}")
        check(row[0] == log[2][2], f"the row names the new holder: {row} vs {log[2]}")
        # The socket half: closed on the NOTIFY, well inside the reload interval.
        check(old.closed is not None and old.closed[0] == 1001 and closed_after < 1.5,
              f"old socket closed 1001 within 1.5 s of the commit: {old.closed} after {closed_after:.2f} s")
        check(new.closed is None, "the new socket is alive")
    finally:
        try:
            hold.rollback()
        except Exception:
            pass
        hold.close()
        for h in (old, new):
            if h:
                await h.stop()
        pg.cursor().execute("UPDATE gateway.node SET state = 'offline' WHERE module = %s", (module,))
        pg.close()


async def scenario_v1_route(gw, tok, route):
    print("20. a path served as API v1 (README § API v1 routes)")
    if not route:
        print("  skipped: no --v1-route")
        return
    twin = "/api/v1/" + route[len("/api/v2/"):]
    parent = route.rsplit("/", 1)[0]

    # A one-segment route has no parent under /api/v2 that is a valid prefix (that one would be a 422).
    held = [("the path itself", [route]), ("a path nested in it", [route + "/x"])]
    if parent != "/api/v2":
        held.append(("a prefix holding it", [parent]))
    for name, prefixes in held:
        ws = await connect(gw, tok, "v1probe", "p1")
        await ws.send(call("/register", register_payload("v1probe", "p1", prefixes=prefixes)))
        r = await rx(ws)
        cc, _ = await close_code(ws)
        check(r["t"] == 4 and r["c"] == 409 and cc == 1008, f"/register {prefixes} ({name}) → 409 + close {cc}")
    ws = await connect(gw, tok, "v1probe", "p2")
    r = await register(ws, "v1probe", "p2", prefixes=[route + "x"])
    check(r["t"] == 3, f"/register [{route}x] (no overlap) → accepted")
    await ws.send(call("/unregister", {"reason": "done"}))
    await rx(ws)
    await close_code(ws)

    r = await asyncio.to_thread(requests.post, f"{gw}{route}", json={}, timeout=5)
    p = r.json() if r.headers.get("Content-Type", "").startswith("application/problem+json") else {}
    check(r.status_code == 401 and p.get("code") == "ERR-401-001" and r.headers.get("WWW-Authenticate") == "Bearer"
          and p.get("instance") == route, f"no token → 401 problem+json, bare challenge ({r.status_code} {p.get('code')})")

    # One body for both: an empty object — the twin refuses it or takes it, either way the two must agree.
    auth = {"Authorization": f"Bearer {tok}"}
    v1 = await asyncio.to_thread(requests.post, f"{gw}{twin}", json={}, headers=auth, timeout=10)
    v2 = await asyncio.to_thread(requests.post, f"{gw}{route}", json={}, headers=auth, timeout=10)
    check(v2.status_code == v1.status_code, f"status as the twin's: v2 {v2.status_code}, v1 {v1.status_code}")
    check(len(v2.headers.get("X-Request-Id", "")) == 36, "X-Request-Id on the answer")
    if v1.status_code < 400:
        check(v2.content == v1.content and v2.headers.get("Content-Type") == v1.headers.get("Content-Type"),
              "success → the twin's body and type, byte for byte")
    else:
        err = v1.json().get("error", {}) if v1.headers.get("Content-Type", "").startswith("application/json") else {}
        p = v2.json() if v2.headers.get("Content-Type", "").startswith("application/problem+json") else {}
        check(p.get("status") == v1.status_code and p.get("instance") == route, f"refusal → problem+json ({p})")
        if str(err.get("error", "")).startswith("ERR-"):
            check(p.get("code") == err["error"] and p.get("type") == "urn:apostol:error:" + err["error"]
                  and p.get("detail") == err.get("message"), f"the twin's identifier kept: {err.get('error')}")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://127.0.0.1:4988")
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--client-secret-file")
    ap.add_argument("--only", help="comma-separated scenario numbers")
    ap.add_argument("--peer", help="second gateway on the same database (scenario 10)")
    ap.add_argument("--pg", help="psycopg2 DSN for reading gateway.node/log (scenario 10)")
    ap.add_argument("--pg-password-file", help="password for --pg (otherwise PGPASSWORD)")
    ap.add_argument("--peer-master-pid", type=int, help="pid of the peer's master process (scenario 12 sends it SIGHUP)")
    ap.add_argument("--pg-container", help="docker container of the database (scenario 15 pauses it for a few seconds)")
    ap.add_argument("--v1-route", help="a path of the gateway's v1_routes (scenario 20)")
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
                 lambda gw, tok: scenario_mirror(gw, tok, args.peer, args.pg),
                 lambda gw, tok: scenario_same_identity(gw, tok, args.peer, args.pg),
                 lambda gw, tok: scenario_fresh_worker(gw, tok, args.peer, args.peer_master_pid),
                 lambda gw, tok: scenario_listen_lost(gw, tok, args.pg),
                 lambda gw, tok: scenario_prefix_handoff(gw, tok, args.pg),
                 lambda gw, tok: scenario_commands_relayed(gw, tok, args.peer, args.pg, args.pg_container),
                 lambda gw, tok: scenario_statement_lost(gw, tok, args.peer, args.pg, args.pg_container,
                                                         args.peer_master_pid),
                 lambda gw, tok: scenario_register_before_load(gw, tok, args.peer, args.peer_master_pid),
                 lambda gw, tok: scenario_register_race(gw, tok, args.peer, args.pg, args.pg_container),
                 lambda gw, tok: scenario_takeover_uncommitted(gw, tok, args.peer, args.pg),
                 lambda gw, tok: scenario_v1_route(gw, tok, args.v1_route)]
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
