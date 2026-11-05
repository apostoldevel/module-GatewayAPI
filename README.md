[![ru](https://img.shields.io/badge/lang-ru-green.svg)](README.ru-RU.md)

Gateway API
-

**Module** for **Apostol CRM**[^crm].

Description
-

**Gateway API** is a C++ module for the [Apostol (C++20)](https://github.com/apostoldevel/libapostol) framework: an API gateway that puts **out-of-process API modules** — written in any language, listening on their own HTTP port — behind the same server, the same authentication and the same cookies as the in-process [AppServer](https://github.com/apostoldevel/module-AppServer).

It runs inside Apostol worker processes and owns two path families:

* `/api/v2/*` — the **data plane**. Every request is authenticated exactly as `AppServer` does it (Bearer JWT, `__Secure-AT` cookie with a transparent refresh, service context) and is then forwarded over HTTP to a module instance chosen by the request path.
* `/gateway/*` — the **control plane**. Module instances connect here over WebSocket, register the path prefixes they serve, send heartbeats and report their state; operators read the routing table and send commands to instances.

Key characteristics:

* Written in C++20 on the asynchronous, non-blocking **epoll** model of the framework; one gateway binary, N worker processes, every worker a full gateway.
* **The module registers itself** — the gateway resolves nothing: an instance connects, says which prefixes it serves and at which `ipv4:port` it listens, and is in rotation the moment its registration is accepted.
* **`GatewayAPI` is an `AppServer`.** It derives from the module and overrides its `execute()` step: authorisation, token refresh and cookies are inherited, only the execution goes elsewhere. `/api/v1/*` stays with `AppServer` untouched.
* **A registry in PostgreSQL** (`gateway.node`, `gateway.log`) mirrors the in-memory table of every worker: the worker holding an instance's socket writes it, the others learn about it through `NOTIFY`, and a periodic re-read plus a sweep cover a lost notification and a dead worker. The gateway keeps routing from memory when the database is away.
* Answers of the gateway itself are **`application/problem+json`** (RFC 9457) with an `X-Request-Id` on every response.

### How it fits into Apostol

```
client ── /api/v1/*  ──► worker: AppServer   ──► daemon.fetch (PostgreSQL)
       ── /oauth2/*  ──► worker: AuthServer
       ── /api/v2/*  ──► worker[i]: GatewayAPI ── HttpProxy ──► module[m,k] at ipv4:port ──► its own database access
       ── /gateway/* ──► worker[j]: GatewayAPI ◄── WebSocket ── module[m,k]   (register, heartbeat, status)
                                      │
                                      └── gateway.node (mirror) ── NOTIFY 'gateway' ──► every worker
```

`i` and `j` are any two workers. A module instance registers with one worker; every worker routes to it. Requests go **gateway → module** over HTTP; the control channel goes **module → gateway** over WebSocket. Nothing of the data plane travels over the WebSocket: HTTP for requests, WebSocket for events.

Control plane
-

### Handshake

```
GET /gateway/{module}/{instance}
Authorization: Bearer <client_credentials token of the configured audience>
Upgrade: websocket
```

`{module}` and `{instance}` match `^[a-z0-9][a-z0-9_-]{0,62}$` and must equal `module` / `instance` in the `/register` frame that follows.

The token is a `client_credentials` JWT issued by [AuthServer](https://github.com/apostoldevel/module-AuthServer) for the audience named in `module.GatewayAPI.audience` — by default `service`, the service client every deployment already has. The gateway verifies the signature, `exp` and `iss` with the provider's secret **and** that `aud` is that provider's `client_id` — a valid token of any other audience is refused. The check runs once, on the handshake; a token expiring while the socket lives does not close it.

A refusal is an HTTP status **before** the `101`, `problem+json` in the body:

| Status | Slug | When |
|--------|------|------|
| `404` | `not-found` | not `{control_path}/{module}/{instance}` |
| `400` | `bad-request` | a segment does not match the pattern |
| `401` | `token-invalid` | no token, bad signature, wrong `aud` / `iss` |
| `401` | `token-expired` | this audience's token expired (403 before T307); an expired token of another audience is `token-invalid` |

(On a framework without the pre-upgrade filter the same refusal arrives as `close 1008` with the reason in the close payload — a module treats both alike.)

**One connection per instance.** A second connection for the same `(module, instance)` **replaces** the first: the new registration wins, the earlier socket is closed `1001 replaced`, the journal records the replacement. Two processes registering under one name therefore displace each other in turn — visible in `gateway.log` as frequent `replaced`, a configuration error of the module, not of the gateway.

**Reconnecting** (module side): back-off `1, 2, 4, 8, 16, 30, 30, …` s with ±20 % jitter, reset after a successful `/register`; reconnect after any disconnect and after `1001` / `1011` / `4000`; after `401` / `403` / `409` / `422` no more often than once in 30 s (the configuration is wrong); after `1000` (its own `/unregister`) do not reconnect.

### Frames

The frame is the JSON-RPC object of [WebSocketAPI](https://github.com/apostoldevel/module-WebSocketAPI): `{t, u, a, p, c, m}`.

| Field | On this channel |
|-------|-----------------|
| `t` | `2` CALL, `3` CALLRESULT, `4` CALLERROR only. `0` OPEN is not used — the socket is authorised by the handshake header; `1` CLOSE is not used — closing is `/unregister` + WebSocket close. An incoming `0` / `1` → CALLERROR `400`, the socket lives |
| `u` | UUID v4 as a string; the reply repeats the `u` of the call. Missing or duplicate `u` → CALLERROR `400` |
| `a` | action path with a leading `/`; only in `t=2`; unknown → CALLERROR `404` |
| `p` | object; absent means `{}` |
| `c`, `m` | only in `t=4`; `c` an integer from the table below, `m` text for a human, not for parsing |

One frame is one text WebSocket message (UTF-8). A binary frame → close `1003`. A frame over **64 KiB** → close `1009`. Every CALL gets exactly one reply, within **5 s** (both directions). A CALL before a successful `/register` (other than `/register` itself) → CALLERROR `409`, the socket lives.

### `/register` — module → gateway

The first frame, within **5 s** of the upgrade (otherwise close `1008`):

```json
{"t":2,"u":"…","a":"/register","p":{
  "module":"clients","instance":"clients-7f3a","version":"0.1.0","build":"8c77181",
  "address":"172.18.0.9:8081","prefixes":["/api/v2/clients"],"capacity":64}}
```

| Field | Type | Required | Rule |
|-------|------|:--------:|------|
| `module` | string | yes | = `{module}` of the URL |
| `instance` | string | yes | = `{instance}` of the URL; a repeated name replaces the earlier socket |
| `version` | string | yes | semver, informational |
| `build` | string | no | build hash or date, informational |
| `address` | string | yes | `"<ipv4>:<port>"`, an **IPv4 literal** — the gateway resolves no names and connects to it as given; must fall within `allowed_cidr`, otherwise `403`. The module's own local address of the WebSocket connection is a good default: it is the address the gateway certainly reaches |
| `prefixes` | string[] | yes, ≥ 1 | each `^/api/v2/[a-z0-9_/-]+$`, no `*`, no trailing `/`. An overlap (equality or nesting) with a prefix of **another** module → `409`; an overlap within the request → `422`. Instances of one module may carry different sets (a rolling update): a route is chosen among the instances **carrying** the matched prefix |
| `capacity` | int | yes | ≥ 1; requests in flight the module accepts from **all** workers together, informational |

The reply **is** `ready` — no separate `/status ready` is needed:

```json
{"t":3,"u":"…","p":{"heartbeat_interval":5,"instance_id":"clients-7f3a","gateway_node":"backend-7c9f:41207",
                    "gateway_worker":41207,"suspect_after":2,"offline_after":4}}
```

`gateway_node` is the identity of the worker that took the socket — `<node>:<pid>` (*Mirror*, **Identity**); `gateway_worker` is its pid alone, kept for readers that predate the identity. All numbers come from the gateway's configuration; the module has none of its own and re-reads them at every registration. A refused registration answers CALLERROR (table below) and closes `1008`; `/register` is not repeated on the same socket. Until the worker's first re-read of `gateway.node` (a fresh worker after a start or `SIGHUP`, about a second) it knows only its own sockets, not the prefixes other modules hold on other workers: a well-formed `/register` is then closed `1013` with no CALLERROR, and the module reconnects with the common back-off and gets its answer — `409` included — from a worker whose table is loaded (T769). The wait lasts at most 10 s from the worker's start: a database still away by then — or three re-reads failed with an error — and the registration is taken against the worker's own sockets, as before, so the worker routes them while it cannot read the table; the first re-read settles a prefix held elsewhere (**Who holds a prefix**).

### `/heartbeat` — module → gateway

Every `heartbeat_interval` seconds (±20 %), the first within one interval of the `/register` reply. `p`: `in_flight` (int ≥ 0, required), `load` (number 0..1, optional). Reply: CALLRESULT `{"state": "<state as the gateway sees it>"}`.

A heartbeat faster than `heartbeat_interval / 2` — measured from the previous **accepted** heartbeat — is answered `429` and dropped. The module sends heartbeats regardless of the replies; after **two unanswered in a row** it closes the socket itself (`4001`) and reconnects. Seeing `suspect` in the reply it does nothing (the next heartbeat returns it to `ready`); seeing `offline` it reconnects.

### `/status` — module → gateway

Immediately on a change: `p` = `{"state": "ready" | "draining" | "overloaded", "reason"?: "…"}`. Reply: CALLRESULT `{}`.

Module transitions: `ready → draining` (SIGTERM, `/drain`) — **irreversible within one socket**, `409` on an attempt back; `ready → overloaded` (`in_flight ≥ capacity`) and back to `ready`. After the CALLRESULT on `draining` no worker sends new requests to the instance (propagation window — see *Instance states*); a module in `draining` **answers** what has already arrived, it does not `503`.

### `/unregister` — module → gateway

The last frame: `{"reason": "shutdown"}`. The module waits up to 2 s for the CALLRESULT and closes `1000`; the gateway closes `1000` itself after the CALLRESULT if the module has not. Without `/unregister` a disconnect is `offline` at once, journaled as `socket closed` — not an error.

### Commands — gateway → module

Over the same socket, reply within 5 s:

| `a` | `p` | Module | Reply |
|-----|-----|--------|-------|
| `/ping` | `{}` | nothing | CALLRESULT `{"in_flight": N}` |
| `/drain` | `{"reason"?: "…", "deadline"?: seconds}` | as on SIGTERM: `/status draining` → waits for requests in flight (≤ `deadline`, default 30) → `/unregister` → close | CALLRESULT `{}` **before** starting |
| `/reload` | `{}` | re-reads its own configuration, not the connection; if `prefixes` / `address` / `capacity` changed it reconnects with a new `/register` | CALLRESULT `{}` |

These are issued through the management endpoints below.

### CALLERROR codes and close codes

| `c` | When | Socket |
|-----|------|--------|
| `400` | frame not parsed; missing or duplicate `u`; `t` not an integer in {2, 3, 4}; JSON nested deeper than 128; `p` not an object; a required field missing or of the wrong type | on `/register` — close `1008`; otherwise lives |
| `403` | `address` outside `allowed_cidr` | close `1008` |
| `404` | unknown `a` | lives |
| `409` | a prefix of another module; a CALL before `/register` | on `/register` — close `1008`; otherwise lives |
| `422` | `module` / `instance` differ from the URL; prefixes overlap within the request; `capacity` < 1; `state` outside the set; a registration whose mirror notification would not fit into 8000 bytes (too many or too long prefixes) | on `/register` — close `1008`; otherwise lives |
| `429` | heartbeat faster than `heartbeat_interval / 2` | lives, frame dropped |
| `500` | internal error of the side | lives |

| Close | Meaning |
|-------|---------|
| `1000` | normal, after `/unregister` |
| `1001` | replaced by a new registration of the same instance |
| `1003` | binary frame |
| `1008` | registration refused; `/register` not received within 5 s; token refused after the upgrade; a prefix lost to an earlier registration of another module, found by a re-read (*Mirror*, **Who holds a prefix**) — the reason is the `409` text |
| `1009` | frame over 64 KiB |
| `1011` | internal error of the gateway |
| `1013` | `/register` before the worker's first re-read — reconnect with back-off |
| `4000` | heartbeat timeout (`offline`) — sent by the gateway |
| `4001` | sent by the **module**: the gateway is silent (two unanswered heartbeats, or `offline` in a reply) — the module closes and reconnects with back-off |

The gateway does not interpret the peer's close code: any close by the peer is `offline` by disconnect.

Instance states
-

| State | In rotation | Set by |
|-------|:-----------:|--------|
| `ready` | yes | the `/register` reply; any `/heartbeat` from `suspect`; `/status ready` from `overloaded` |
| `suspect` | no | `now − last_heartbeat ≥ suspect_after × heartbeat_interval` — by the clock, not by a counter; or **5 consecutive connection failures** on the data plane (per worker; the counter resets on a successful answer or a heartbeat) |
| `draining` | no | `/status draining`; irreversible on this socket |
| `overloaded` | no | `/status overloaded`; until `/status ready` |
| `offline` | no | `≥ offline_after × heartbeat_interval` of silence → close `4000`; `/unregister`; any disconnect — at once; the sweep of a dead worker's rows |

Windows: a frame is answered within 5 s (both sides); `draining` accepted → every worker has stopped routing to the instance within **≤ 1 s** (`NOTIFY`) or, if a notification is lost, within `reload_interval`. A row nobody has touched for `(offline_after + 1) × heartbeat_interval` is swept to `offline` by any worker.

Routing table
-

Every worker keeps the full table — its own sockets plus the other workers' instances from the mirror:

```
module ──► instance ──► { address, prefixes[], state, capacity,
                          in_flight (this worker's local counter), conn_errors,
                          last_heartbeat, owner_node, owner_worker, source ∈ {socket, mirror} }
```

**Route resolution:** the longest prefix, among the instances in `ready` that carry it. **Instance choice:** the least local `in_flight`; ties by round robin. No prefix covers the path → `404 no-route` — once the worker has read the table; before its first re-read → `503 routes-loading` with `Retry-After: 1`; a prefix exists but no instance is `ready` → `503 no-instance` with `Retry-After: 1`. Tell them apart by `type`, not by `detail`. Prefix matching is by path segment: `/api/v2/clients` covers `/api/v2/clients` and `/api/v2/clients/…`, not `/api/v2/clients2`.

Data plane
-

`/api/v2/*` goes through `AppServer::do_fetch`: response-shaping parameters, payload, `check_auth` — Bearer JWT verified locally, `__Secure-AT` / `__Secure-SAT` cookies, an expired cookie token refreshed through `daemon.refresh_token` with the new cookies set on the answer — and then `execute()`, which here forwards the request instead of calling `daemon.fetch`.

**Gateway → module** (`HttpProxy`): HTTP/1.1, `Connection: close` (one TCP connection per request), `Host: <address>`. Method, path, query and body as the client sent them; `Content-Length` is always present (set by the gateway on a chunked request).

### Headers

Upstream, on the copy that reaches the module:

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <AT>` — the client's, as it is after verification, or the token of the `__Secure-AT` cookie (`__Secure-SAT` under `X-Auth-Context: service`), the **new** one after a refresh. **Absent if the client had nothing** — then the module answers `401`. `Basic`, `Session`, `Secret` pass as they are |
| `X-Auth-Context` | as received |
| `X-Request-Id` | UUID v4 **minted by the gateway**; a client-supplied one, if any, moves to `X-Client-Request-Id` and is not trusted |
| `X-Forwarded-For` | **exactly one address**: the last element of the incoming header (a reverse proxy in front appends the real client address to whatever the client sent), or the peer address when there is none |
| `X-Forwarded-Proto` | `https` |
| `X-Gateway-Worker` | identity of the worker, `<node>:<pid>` (*Mirror*, **Identity**) — a pid alone repeats between pods |
| `User-Agent`, `Accept`, `Accept-Language`, `Content-Type`, `If-Match`, `If-None-Match`, `Idempotency-Key`, … | as received |
| `Cookie` and hop-by-hop headers | **always removed** |

Downstream, on the module's answer before it reaches the client: status and body as the module sent them; hop-by-hop headers and **`Set-Cookie` of the module removed** (cookies are set by the refresh only); `X-Request-Id` forced to the gateway's; the refresh's `Set-Cookie`, if there was one, added. The module should return `X-Request-Id` with the same value and should not use `Transfer-Encoding: chunked` (`HttpProxy` buffers the whole answer).

### Errors

Everything the gateway answers on its own is `application/problem+json` (RFC 9457):

```json
{"type":"urn:apostol:gateway:no-route","title":"Not Found","status":404,
 "detail":"no prefix covers the path","instance":"/api/v2/nowhere/1",
 "request_id":"1f9f6a2e-…","code":null}
```

| Status | Slug | When | Headers |
|--------|------|------|---------|
| `400` | `bad-request` | refused before routing (`result_object` / `result_format` values, payload transformer) | |
| `401` | `token-invalid` — `code` `ERR-401-001` | no token (control plane), signature, `aud`, `iss`, not a token | `WWW-Authenticate: Bearer error="invalid_token"` |
| `401` | `token-expired` — `code` `ERR-401-008` | access token expired and no refresh possible (RFC 6750 §3.1) | `WWW-Authenticate: Bearer error="invalid_token"` |
| `401` | `token-expired` — `code` `ERR-401-008` | expired token of the gateway audience on the control plane (was 403 before T307); an expired token of **another** audience is answered as `token-invalid`, like a valid one of another audience | `WWW-Authenticate: Bearer error="invalid_token"` |
| `404` | `no-route` | no prefix covers the path | |
| `404` | `unknown-instance` | a command for an instance the worker's table does not know, or knows `offline` | |
| `405` | `method-not-allowed` | `PUT` / `PATCH` / `DELETE` on the control path | `Allow: GET, POST` |
| `502` | `upstream-error` | connection or answer failed, retry impossible or exhausted | |
| `503` | `no-instance` | the route exists, no instance is `ready` | `Retry-After: 1` |
| `503` | `routes-loading` | no prefix covers the path **before the worker's first re-read** (contract edition 6, K7) — a fresh worker (a restart by the master, `SIGHUP`) knows only its own sockets until then, so "no route" is not known yet; the same for a command's instance. After three re-reads that fail with an error (no schema, no grant — not a database that is merely away) the worker stops waiting and answers `404 no-route` from its own sockets (logged `routing table not loaded after N failed reloads`) | `Retry-After: 1` |
| `503` | `database-unavailable` | a command to relay (another worker holds the socket), and the database refused it, or did not confirm it within 9 s and no holder answered, or this worker is not listening on `gateway_cmd` yet | `Retry-After: 1` |
| `504` | `upstream-timeout` | no complete answer within `response_timeout_ms`; a command not answered in 5 s; a relayed command no worker answered in 9 s | |
| other | `refresh-refused`, `internal` | the database refused the refresh with a status other than 401; an internal error | |

`code` is `null` except on a `401`, which carries the catalogue id the go-platform host gives the same case — every way a token fails to verify is `ERR-401-001` (a separate "bad signature" id would tell a prober which check it passed). Every `401` carries `WWW-Authenticate` (RFC 6750 §3): a bare `Bearer` when the request carried no credentials at all (no `Authorization`, another scheme, an empty token — §3.1; the data plane never answers that itself, it passes such a request on to the host), otherwise `Bearer error="invalid_token"`, with `error_description` only when `detail` is within the §3 alphabet (printable ASCII without `"` and `\`) — the same rule as the host.

A module answers in the same shape with `type = urn:apostol:error:<code>` and `code` set; the gateway passes such answers through untouched.

### Timeouts and retry

Connect: `connect_timeout_ms` (1 s). Answer, from sending the request to the last byte: `response_timeout_ms` (30 s); a module should answer within 25 s and must not hold a transaction longer than the answer.

**Exactly one retry, on another `ready` instance, only when the connection was not established** (refused or timed out on connect) — not a byte of the request has left. Once sent, never retried: the module may have executed it; a broken connection or a timed-out answer is `502` / `504`, and idempotency of `POST` is the caller's `Idempotency-Key`, not a retry. No other instance → `502`. A connection failure counts towards the passive check (5 → `suspect`).

Mirror
-

The database half of the module is the **`gateway`** module of [db-platform](https://github.com/apostoldevel/db-platform): schema `gateway` with `node` (one row per instance: `module`, `instance`, `version`, `address`, `prefixes`, `state`, `capacity`, `worker`, `node`, `registered`, `seen`, `updated`), `log` (one row per transition: `state_from`, `state_to`, `worker`, `node`, `reason`), the view `route` (prefix → module → `instances_ready` / `instances_total`, for other applications) and the trigger that journals every transition and issues `pg_notify('gateway', {op, module, instance, state, state_from, address, prefixes, worker, node, updated})`. `updated` is `now()` of the writing transaction — not a version: two notifications are never ordered by it, and the gateway does not read it.

**Identity.** A worker is the pair **(node, pid)**: `node` is the application's `node_id()` — the top-level `"node"` of the configuration, else `$NODE_NAME` (in Kubernetes, the pod name from the downward API), else the host name — and `pid` its process id. A pid alone repeats between pods and containers on one database, and two workers taking each other's rows for their own close them in turn every re-read. A row is a worker's own only when **both** `gateway.node.node` and `gateway.node.worker` are its; a row with `node` NULL — written by a gateway that does not know the column — is never anyone's own, whatever its pid. Every write sets `node` explicitly, on the `ON CONFLICT` branch too: a binary that does not know the column leaves it as it was, so while old and new gateways share a database a row may carry one worker's node next to another's pid, and the pair, never the pid, decides. The identity reads `<node>:<pid>` wherever it is shown: `gateway_node` of the `/register` reply and of the management answers, `X-Gateway-Worker`, the sender of a command between workers, the log. The column comes with the `gateway` module of db-platform 1.2 patch `P00000032`; a gateway of this version writes it on every statement and needs it in the database.

**Who writes:** only the worker holding the instance's socket. On `/register` the existing row is first closed in the journal (`replaced` when a live socket was displaced here, `re-registered` otherwise) and then written `ready` (`registered`) — so the journal never shows `ready → ready` with a new address, and the other workers get an `offline` they can act on before the `ready` that re-points them. Every upsert of one `(module, instance)` — a registration or a re-assert — is written one at a time across workers and pods: it takes a transaction-scoped advisory lock on the pair first; without it a second registration on another worker, a few milliseconds after the first and before that one has committed, found no row to close, waited for the first `INSERT` and turned `ready` into `ready` — no transition, no `NOTIFY`, and the earlier socket stayed open until its worker's next re-read (T1211). The lock orders the writes, it does not choose which comes first: a registration whose write waits in its worker's queue may still commit after a later one on another worker, and then holds the row. Every transition is an `UPDATE` with the reason passed to the trigger through the transaction-local GUC `gateway.reason`. `seen` moves **once per `heartbeat_interval`**, for the instances that heartbeated in it — the trigger stays silent on an `UPDATE` that changes no state, so a fleet of modules cannot turn the channel into a metronome. All writes of a worker go through one queue: the connection pool would otherwise reorder two statements sent back to back.

**Who reads:** every worker `LISTEN`s `gateway` and applies the payload at once (it carries everything routing needs); every `reload_interval` it re-reads the whole table and reconciles — its own rows are re-asserted where the database disagrees (`owner re-asserted`), rows naming its identity without a socket behind them are closed (`no socket on worker`), foreign rows — a row with its pid and another node or none included — are mirrored, mirrored rows gone from the table go `offline`. The first re-read runs right at start: until it lands, a miss is `503`, not `404`. With a libapostol that confirms `LISTEN` (`APOSTOL_PG_LISTEN_READY`) the worker also re-reads on every confirmation — the first subscription and each re-subscription after the pool replaced a lost listener — so a NOTIFY committed while the listener was down is found at once, not a `reload_interval` later. In the same transaction it sweeps rows of **other** workers whose `seen` is older than `(offline_after + 1) × heartbeat_interval` — one interval more than the owner's own clock, so a live owner always beats the sweep and it only finishes what a dead worker left behind. By `seen`, not by pid; "other" is by identity.

**Who is right:** a notification about its own row does not move a worker — `node` and `worker` of the payload are the row's columns, not the writer's, and the offline step of another worker's `/register` still carries the previous identity. Only a state other than `offline` with **another** identity acts on an owned row, and only as a signal: the worker reads the row back from `gateway.node` — behind its own queued writes — and acts on the row, not on the payload. If the row names another worker, the earlier socket is closed `1001 replaced` and the row becomes a mirror; if it still names this one (a forged or stale notification), the socket stays. A takeover whose notification was lost is found by the periodic re-read, which acts on the row the same way. With the database away the gateway routes from memory — its own sockets are the truth, foreign instances are the last known copy — and says so once per `reload_interval`.

**Who holds a prefix:** two modules registering overlapping prefixes on two workers at once (within a notification's delay) are both accepted — each worker checks against what it knows. Every re-read then settles it the same way on every worker: the live rows of the snapshot and the worker's own sockets (an own socket whose row the snapshot does not show yet counts as registered after all of them) are taken in the order of `gateway.node.registered` — the database's clock — ties by module, then instance; each holds its prefixes unless one overlaps a prefix already held by another module. A row that holds nothing is refused (`mirror row refused (reload): prefix … belongs to module …`); an own socket that holds nothing is written `offline` and closed `1008` with that reason, and the module comes back to a `409`. Until that re-read (`reload_interval` at most) the two workers route the overlap differently. Instances of one module never compete.

**What is trusted:** commands between workers are signed (*Commands across workers*); the mirror is not — its notifications come from a trigger. A row that did not come through `/register` — a NOTIFY payload or a row read back — gets the same checks before it touches the table: `address` an IPv4 literal inside `allowed_cidr`, `prefixes` a non-empty array of valid, non-overlapping prefixes. `pg_notify` is open to any role with `CONNECT`; without the checks a forged payload would point `/api/v2/*`, users' Bearer tokens included, at an address of its choosing. A refused row changes nothing — no new mirror, no re-pointed address, no takeover of a live socket — and is logged `mirror row refused (notify|reload): <why>`; a mirror whose row turns unacceptable on a re-read goes `offline`. A payload that copies a real address and prefix passes these checks; it still cannot close a live socket, because a takeover acts on the row read back (**Who is right**), and a notification writes nothing to the table. What such a payload can still do is re-point **a mirror** — another worker's instance — within `allowed_cidr` until the next re-read or notification; a notification is trusted for the instances a worker only mirrors. The table itself is written by the database roles `daemon` and `apibot` (db-platform grants both `INSERT`, `UPDATE` and `DELETE` on `gateway.node`), and the gateway cannot tell its own workers from any other process that connects as one of them: a row written under these roles that passes the checks above is believed, and it can re-point an instance within `allowed_cidr` or take over a live socket, as a `/register` can. Such a row also takes part in **Who holds a prefix**: with an early `registered` and a broad prefix it has every live socket of another module overlapping it closed `1008` on its worker, and the module comes back to a `409`. The credentials of these two roles are inside the trust boundary.

Management endpoints
-

All under `control_path`, with a Bearer token of the gateway audience; answers are JSON or `problem+json`.

### `GET /gateway/list`

The table of this worker:

```json
{"gateway_node":"backend-7c9f:41207","gateway_worker":41207,"heartbeat_interval":5,"suspect_after":2,"offline_after":4,
 "instances":[{"module":"clients","instance":"clients-7f3a","version":"0.1.0","build":"8c77181",
               "address":"172.18.0.9:8081","prefixes":["/api/v2/clients"],"capacity":64,
               "state":"ready","in_flight":3,"load":0.2,"local_in_flight":1,"conn_errors":0,
               "registered_s":812,"seen_s":2,"owner_node":"backend-7c9f","owner_worker":41207,"source":"socket"}]}
```

`source` is `socket` for an instance registered with this worker and `mirror` for one learned from the database; `owner_node` / `owner_worker` — the identity of the worker holding the socket (`owner_node` null for a row written without it); `in_flight` is what the instance reported, `local_in_flight` this worker's own counter.

### `GET /gateway/route?path=/api/v2/…`

Where the path would go from this worker right now — the same resolution the data plane runs, with the same `404` / `503`, without a request. It moves the round-robin cursor like a real request would.

```json
{"gateway_node":"backend-7c9f:41207","gateway_worker":41207,"path":"/api/v2/clients/7","module":"clients","instance":"clients-7f3a",
 "address":"172.18.0.9:8081","local_in_flight":1}
```

### `POST /gateway/{module}/{instance}/ping` · `/drain` · `/reload`

Sends the command over the instance's socket and answers with the module's CALLRESULT payload (`{"in_flight": N}` for `/ping`, `{}` otherwise); a CALLERROR from the module → `502`, no answer in 5 s → `504`. The body, a JSON object, goes to the module as the CALL's `p`. Any worker takes the command, whichever holds the socket: an instance its table does not know, or knows `offline`, is `404 unknown-instance`; one held elsewhere is relayed (below).

#### Commands across workers

Only the worker holding an instance's socket can talk to the module, and a worker has no address of its own — every worker, and every pod, shares the listening socket. So a command that lands elsewhere goes through the database: `NOTIFY gateway_cmd` carries it to every worker, the one holding the socket sends the CALL and puts the module's answer on the same channel, and the relaying worker matches the answer to the waiting request by the command's id. A message names its sender by identity — `from` of a command, `by` of an answer, `<node>:<pid>` — for the log only.

- **Signed.** `pg_notify` is open to any role with `CONNECT`, and `LISTEN` shows it every payload; an unsigned command would let any of them drain a module — irreversibly. A message is `<HMAC-SHA256 hex>.<json>`; the key is `HMAC-SHA256(client_secret of the audience, "apostol:gateway_cmd")` — a key of the channel's own, not the secret that signs the audience's tokens. Every gateway process verifies the audience's tokens, so every one has the secret; a message that fails the check is dropped and logged `gateway_cmd message refused: <why>`, once per `reload_interval` with a count. No secret configured — a relayed command is `500 internal`. **What the signature does not cover:** whoever holds the audience secret — with the default audience `service`, every module, which mints its own token with it — can sign too. A forged *command* gives a module nothing it lacks (its token opens `POST /gateway/…` anyway), but a module that may `LISTEN` can answer a command meant for another module before the real answer arrives. Where that matters, give the gateway an audience of its own.
- **A deadline and an id.** A command carries a deadline 2 s ahead, and a holder that gets it later drops it: with the database away a query waits in the pool's queue and never fails, and a drain queued then must not run once the database is back. The relaying worker waits 9 s — past the deadline, the holder's own 5 s and its clock tick — so the answer of any holder that took the command arrives first; with none, it answers `503 database-unavailable` when `pg_notify` never returned (immediately when the database refused it) and `504` otherwise. The deadlines compare wall clocks: across pods they rely on NTP. Within the deadline a replayed message — or the statement the pool re-sends after a lost connection — is stopped by its id.
- **Answers.** The holder answers what it would answer a caller of its own — `200`, `502`, `504` after 5 s. With no holder anywhere (a row the table still shows `ready`), the relaying worker answers `504` after 9 s; the same when its own `LISTEN gateway_cmd` is down — the pool re-subscribes but does not report the loss, so the answer is published to nobody. An answer that does not fit into a notification (8000 bytes) becomes `502`; a command body that does not fit is `400`.
- **Visible.** The payload travels in clear: whoever may `LISTEN` sees the command, its body and the module's answer — keep secrets out of command bodies.

Configuration
-

Section `module.GatewayAPI` of the application's JSON configuration:

```json
"GatewayAPI": {
  "enable": true,
  "control_path": "/gateway",
  "heartbeat_interval": 5,
  "suspect_after": 2,
  "offline_after": 4,
  "connect_timeout_ms": 1000,
  "response_timeout_ms": 30000,
  "reload_interval": 60,
  "allowed_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "audience": "gateway"
}
```

| Key | Default | Meaning |
|-----|---------|---------|
| `enable` | `false` | the module is off unless switched on |
| `control_path` | `/gateway` | control plane and management endpoints; the data plane is always `/api/v2/*` |
| `heartbeat_interval` | `5` | seconds; handed to the module in the `/register` reply; also the period of the `seen` write |
| `suspect_after` | `2` | intervals of silence → `suspect` |
| `offline_after` | `4` | intervals of silence → `offline`, close `4000`; always > `suspect_after` |
| `connect_timeout_ms` | `1000` | connect to the module |
| `response_timeout_ms` | `30000` | from sending the request to the last byte of the answer |
| `reload_interval` | `60` | seconds between re-reads of `gateway.node` and sweeps |
| `allowed_cidr` | `[]` | IPv4 networks `a.b.c.d/n` an instance may register an `address` in; an empty list refuses every registration with `403`. An array, or one comma-separated string — the form a value from the environment takes (`"allowed_cidr": "${GATEWAY_ALLOWED_CIDR}"`, substitution works inside strings only); a blank string is the default. An entry that does not parse — or is not a string, or a value of another type — is skipped with a warning; `/00` does not parse (it would read as `/0`) |
| `audience` | `service` | the OAuth2 provider (section of `oauth2/*.json`) whose tokens open the control plane |

The worker's identity is not a key of this section: it is the application's `node` (top level of the configuration, e.g. `"node": "${NODE_NAME}"`), else `$NODE_NAME`, else the host name (*Mirror*, **Identity**). Two gateway processes on one database must not share a node name unless they share a PID namespace too. In Kubernetes set `NODE_NAME` from `metadata.name` (the pod), **not** `spec.nodeName` (the machine: two pods on one machine would share it); in docker the container's host name is unique — except with `network_mode: host`, an explicit `hostname:`, or `hostNetwork: true` in Kubernetes, where it is the machine's or a shared one: set `node` explicitly there.

Installation
-

Follow the build and installation instructions for [Apostol (C++20)](https://github.com/apostoldevel/libapostol#build-and-installation). The module needs `AppServer` in the same tree (it derives from it) and the `gateway` module of db-platform in the database.

**Registration.** The module is registered **before** `AppServer` (first match wins: `/api/v2/*` and the control path go to the gateway, `/api/v1/*` stays with `AppServer`). The application has one WebSocket handler and one pre-upgrade filter; the split between the gateway and `WebSocketAPI` is by path:

```cpp
GatewayAPI* gateway_raw = nullptr;
if (app.module_enabled("GatewayAPI", /*default_val=*/false) && app.has_db_pool()) {
    auto gateway = std::make_unique<GatewayAPI>(app);
    gateway_raw = gateway.get();
    app.module_manager().add_module(std::move(gateway));
}
if (app.module_enabled("AppServer") && app.has_db_pool())
    app.module_manager().add_module(std::make_unique<AppServer>(app));
// …
app.set_ws_upgrade_filter([gateway_raw](const HttpRequest& req, HttpResponse& resp) {
    if (gateway_raw && gateway_raw->owns_ws_upgrade(req))
        return gateway_raw->ws_upgrade_allowed(req, resp);   // 404/400/401 before the 101
    return true;
});
app.set_ws_handler([ws_api_raw, gateway_raw](EventLoop& loop, WsConnection ws, const HttpRequest& req) {
    if (gateway_raw && gateway_raw->owns_ws_upgrade(req)) { gateway_raw->on_ws_upgrade(loop, std::move(ws), req); return; }
    if (ws_api_raw) { ws_api_raw->on_ws_upgrade(loop, std::move(ws), req); return; }
    ws.send_close(1008, "not-found");
});
```

**OAuth2 audience.** The control plane is opened by `client_credentials` tokens of the provider named in `audience` — by default the `service` provider of `oauth2/*.json`, which every Apostol deployment has (client_id `service-${DOMAIN}`, secret from `CLIENT_SECRET_SERVICE`); modules obtain their token from `POST /oauth2/token` with that client. A dedicated provider is possible (`audience` names it; the matching audience must exist in the database — `AddApplication` + `CreateAudience` of db-platform), but not required. At start the module logs an error if the provider is missing or its secret is empty — every module would be refused with nothing but close reasons to show for it.

**Database.** Schema `gateway` from db-platform (module `gateway`, in `create.psql` / `update.psql`, or its patch on an existing database) **with the `node` column** (patch `P00000032`): this version writes it in every statement, and without it every mirror write fails — apply the schema first, then roll the binary; a gateway that predates the column works on the new schema, but not **next to** this version: it leaves `node` as it was on a row it takes over, and between PID namespaces the resulting pair can match a worker of this version — the old flapping again. Roll every gateway of one database at once (or shrink to one first). The worker pool role needs `SELECT, INSERT, UPDATE, DELETE` on `gateway.node` and `INSERT` on `gateway.log` — granted by the module's `table.sql`.

Self-test
-

`tests/stub_client.py` plays the module side without a real module and checks the gateway in both directions — every refusal is provoked on purpose. It needs a running gateway, a `client_credentials` provider and Python 3 with `requests`, `websockets` and (for the mirror scenario) `psycopg2`:

```bash
python3 tests/stub_client.py --gateway http://127.0.0.1:4977 \
    --client-id service-example.com --client-secret-file /path/to/secret
# mirror scenario: a second gateway process on the same database plays the second worker
python3 tests/stub_client.py … --peer http://127.0.0.1:4978 \
    --pg "host=127.0.0.1 port=5432 dbname=example user=daemon" --pg-password-file /path/to/pgpass
```

The stub expects `heartbeat_interval` 2, `reload_interval` 5, `response_timeout_ms` 2000 and `127.0.0.0/8` in `allowed_cidr` of the gateways it runs against (see its header). Scenarios: registration and its refusals, handshake refusals, the clock (`suspect` / `offline`), commands, replacement, frames, routing, the data plane with an echo module, the mirror with a second worker, a fresh worker after `SIGHUP`, a lost `LISTEN`, a prefix handoff seen only by a re-read, commands relayed through the second worker — forged, replayed and late ones included (`--pg-container` pauses the database's container for the late one). Number 11 — two workers under one pid — needs the two gateways in PID namespaces of their own (a container each, the network shared) and is skipped otherwise: with different node names an instance stays `ready` over three re-reads with no `no socket on worker`; with one node name, or on a gateway that tells workers apart by pid alone, the other worker closes the live row every re-read. Number 16 — the negative control for `PgRetry::if_lost` — cuts the pool's connections off with a statement in the server's hands (`pg_terminate_backend`; `--pg-container` stops the backends so the command is caught in flight): a relayed `pg_notify` must be sent again (the module answers, 200, not 503), and a fresh worker whose first re-reads are cut off must keep answering 503 `routes-loading`, never 404; on a gateway whose pool does not repeat them, both are red.

[^crm]: **Apostol CRM** — a template project built on the [A-POST-OL](https://github.com/apostoldevel/libapostol) (C++20) and [PostgreSQL Framework for Backend Development](https://github.com/apostoldevel/db-platform) frameworks.
