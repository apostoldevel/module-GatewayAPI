#pragma once

// GatewayAPI — an API gateway in front of out-of-process API modules. The
// protocol, the states, the headers and the mirror are specified in README.md;
// the comments below refer to its sections.
//
// Two planes. The CONTROL plane and the in-memory routing table (README
// § Control plane, § Routing table): API modules connect over WebSocket to
// /gateway/{module}/{instance}, register, send heartbeats and status; the
// worker holding the socket keeps the instance in its table and drives
// ready/suspect/draining/overloaded/offline by the clock.
//
// The DATA plane (/api/v2/* → HttpProxy, README § Data plane) is the
// AppServer execute() seam: this module IS an AppServer that keeps check_auth
// and the cookie token refresh and overrides execute() — the request goes to
// a module instance over HttpProxy instead of daemon.fetch. The MIRROR
// (README § Mirror): the worker that owns an instance's socket writes
// gateway.node on every transition and `seen` once per interval; every worker
// LISTENs `gateway` and keeps the other workers' instances in its table as
// source=mirror, re-reads the whole table every reload_interval and sweeps
// rows nobody has touched for (offline_after + 1) intervals. Memory is the
// truth for own sockets even when the database is not there.
//
// The frame protocol is WebSocketAPI's {t,u,a,p,c,m} (module-WebSocketAPI,
// README § RPC Protocol). Only t=2/3/4 are used on this channel; the socket
// is authorised by the handshake header (Bearer service token of the
// configured audience), never by an OPEN frame.

#include "../AppServer/AppServer.hpp"

#include "apostol/http_proxy.hpp"
#include "apostol/pg.hpp"
#include "apostol/websocket.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace apostol {

class Application;
class EventLoop;

class GatewayAPI final : public AppServer
{
public:
    explicit GatewayAPI(Application& app);

    std::string_view name() const override { return "GatewayAPI"; }
    bool enabled() const override { return enabled_; }
    bool check_location(const HttpRequest& req) const override;
    void heartbeat(std::chrono::system_clock::time_point now) override;
    /// Drops the HttpProxy objects while the EventLoop is still alive. Not for
    /// ~HttpProxy — it never touches the loop — but for the in-flight forwards
    /// it owns: ~ForwardCtx → ~TcpClient cancels its timers and removes its fd
    /// from the loop, and modules are destroyed with the Application, after
    /// the loop (a local of *_run) is gone — measured as a SIGSEGV on SIGTERM
    /// after data-plane traffic.
    void on_stop() override;

    /// True if @p req is a WebSocket upgrade for this module's control_path.
    /// The application's ws_handler asks this before handing an upgrade to
    /// WebSocketAPI (README § Installation).
    bool owns_ws_upgrade(const HttpRequest& req) const;

    /// The pre-upgrade filter (Application::set_ws_upgrade_filter): the HTTP
    /// refusal — 404 unknown control path, 401 token-invalid, 403
    /// token-expired as problem+json — BEFORE the 101. Returns true to let the
    /// upgrade through. Called from the filter lambda the application installs
    /// (README § Installation).
    bool ws_upgrade_allowed(const HttpRequest& req, HttpResponse& resp) const;
    /// The one predicate behind both: "" when the handshake may proceed, else
    /// not-found | bad-request | unauthorized | forbidden (README § Handshake).
    std::string handshake_refusal(const HttpRequest& req, std::string& module, std::string& instance) const;

    /// Called from the application's ws_handler lambda, after the 101. The
    /// checks of ws_upgrade_allowed() run again here as the fallback for a
    /// build without the filter: a refusal at this point is a close 1008 with
    /// the reason in the close payload.
    void on_ws_upgrade(EventLoop& loop, WsConnection ws, const HttpRequest& req);

    // ── Routing table (README § Routing table) ─────────────────────────────

    enum class Source { socket, mirror };

    struct Instance
    {
        std::string module;
        std::string instance;
        std::string version;
        std::string build;
        std::string address;     // "ipv4:port" as registered
        std::string host;        // ipv4 literal
        uint16_t    port{0};
        std::vector<std::string> prefixes;
        int         capacity{0};
        std::string state{"ready"};   // ready | draining | overloaded | suspect | offline
        int         reported_in_flight{0};
        double      load{0.0};
        int         in_flight{0};     // local counter of THIS worker (data plane)
        int         conn_errors{0};   // consecutive connect failures (passive check)
        std::chrono::system_clock::time_point registered;
        std::chrono::system_clock::time_point last_heartbeat;
        int         owner_worker{0};
        Source      source{Source::socket};
    };

protected:
    void init_methods() override;

    /// The AppServer seam: authorisation settled by AppServer::do_fetch, the
    /// request goes to a module instance over HttpProxy (README § Data plane)
    /// instead of daemon.fetch.
    void execute(const HttpRequest& req, std::shared_ptr<HttpConnection> conn,
                 const ExecContext& ctx, std::string_view method,
                 const std::string& payload, const ResultShaping& shaping) override;

    /// Every refusal AppServer produces itself — check_auth synchronously, the
    /// refresh callback asynchronously — as the gateway's problem+json (README
    /// § Errors): invalid → 401 token-invalid, expired / refresh_failed /
    /// database-401 → 401 token-expired, the rest by status.
    void reply_refused(HttpResponse& resp, const Refusal& refusal) override;

private:
    // ── One WebSocket connection = one node ────────────────────────────────

    struct PendingCall
    {
        std::string action;
        std::chrono::system_clock::time_point sent;
        // HTTP request waiting for the module's answer (POST /gateway/…/ping etc.)
        std::shared_ptr<void> http_conn;
    };

    struct Node
    {
        std::shared_ptr<WsConnection> ws;
        std::string module;
        std::string instance;
        std::string peer_ip;
        bool        registered{false};
        bool        closing{false};
        std::chrono::system_clock::time_point connected;
        std::chrono::system_clock::time_point close_deadline;   // valid while closing
        std::map<std::string, PendingCall> pending;   // our CALLs to the module, by u
    };

    // ── HTTP (GET /gateway/list, POST /gateway/{m}/{i}/{ping|drain|reload}) ──

    void do_get(const HttpRequest& req, HttpResponse& resp);
    void do_post(const HttpRequest& req, HttpResponse& resp);
    void do_put(const HttpRequest& req, HttpResponse& resp)    { data_plane(req, resp, "PUT"); }
    void do_patch(const HttpRequest& req, HttpResponse& resp)  { data_plane(req, resp, "PATCH"); }
    void do_delete(const HttpRequest& req, HttpResponse& resp) { data_plane(req, resp, "DELETE"); }

    /// /api/v2/*: AppServer::do_fetch (check_auth, refresh) → execute(). A
    /// synchronous 401/403 from check_auth is rewritten to problem+json.
    void data_plane(const HttpRequest& req, HttpResponse& resp, std::string_view method);
    bool is_data_path(std::string_view path) const;

    // ── Data plane: forward, retry, passive check (README § Data plane) ─────

    struct Upstream
    {
        std::unique_ptr<HttpProxy> proxy;
        int in_flight{0};
    };
    Upstream& upstream_for(const Instance& inst);
    void forward_to(Instance& inst, HttpRequest up, std::shared_ptr<HttpConnection> conn,
                    const ExecContext& ctx, std::string request_id, int attempt);
    void answer_problem(const std::shared_ptr<HttpConnection>& conn, const ExecContext& ctx,
                        int status, std::string_view slug, std::string_view title,
                        std::string_view detail, std::string_view path,
                        std::string_view request_id, bool retry_after = false) const;

    /// Verify the Bearer against the gateway audience. Returns "" when ok,
    /// otherwise a short reason ("unauthorized" / "forbidden").
    std::string check_gateway_token(const HttpRequest& req) const;
    /// problem+json (RFC 9457) the gateway's way: type urn:apostol:gateway:<slug>,
    /// code null, X-Request-Id — minted here unless @p request_id is given
    /// (the data plane has one already: the one the module saw).
    void reply_problem(HttpResponse& resp, int status, std::string_view slug,
                       std::string_view title, std::string_view detail,
                       std::string_view instance_path, std::string_view request_id = {}) const;

    // ── WebSocket ──────────────────────────────────────────────────────────

    std::shared_ptr<Node> add_node(WsConnection ws, std::string module,
                                   std::string instance, std::string peer_ip);
    void close_node(const std::shared_ptr<Node>& node, uint16_t code,
                    std::string_view reason);
    void drop_node(const std::shared_ptr<Node>& node);   // epoll detach + table update after a close/EOF

    void on_ws_message(const std::shared_ptr<Node>& node, uint8_t opcode,
                       const std::string& payload);
    void on_call(const std::shared_ptr<Node>& node, const std::string& u,
                 const std::string& action, const nlohmann::json& p);
    void on_reply(const std::shared_ptr<Node>& node, const nlohmann::json& msg);

    void handle_register  (const std::shared_ptr<Node>& node, const std::string& u, const nlohmann::json& p);
    void handle_heartbeat (const std::shared_ptr<Node>& node, const std::string& u, const nlohmann::json& p);
    void handle_status    (const std::shared_ptr<Node>& node, const std::string& u, const nlohmann::json& p);
    void handle_unregister(const std::shared_ptr<Node>& node, const std::string& u, const nlohmann::json& p);

    static void send_call_result(WsConnection& ws, std::string_view u, const nlohmann::json& p);
    static void send_call_error (WsConnection& ws, std::string_view u, int code, std::string_view message);
    void send_call(const std::shared_ptr<Node>& node, std::string_view action,
                   const nlohmann::json& p, std::shared_ptr<void> http_conn = {});

    // ── Table ──────────────────────────────────────────────────────────────

    Instance* find_instance(const std::string& module, const std::string& instance);
    /// The registered, not-closing node behind (module, instance) on THIS
    /// worker, or nullptr.
    std::shared_ptr<Node> socket_of(const std::string& module, const std::string& instance) const;
    /// True when this worker writes the row: it holds the socket.
    bool owns(const Instance& inst) const
    { return inst.source == Source::socket && inst.owner_worker == pid_; }

    /// Route resolution + instance choice (README § Routing table). Longest
    /// prefix among instances in `ready` that carry it; among those the least
    /// local in_flight, ties by round robin. `avoid_address` — the address a
    /// retry must not hit again (one retry, on ANOTHER instance); by
    /// address, not by row, because the failed row may be swept or replaced
    /// by the time the failure is reported. Empty — no exclusion. nullptr with
    /// `covered` false → 404 no-route (no prefix of any instance, in any state,
    /// covers the path); nullptr with `covered` true → 503 no-instance.
    /// Only `ready` is in rotation: suspect, draining, overloaded, offline are
    /// out (README § Instance states).
    Instance* pick_instance(std::string_view path, std::string_view avoid_address, bool& covered);
    static bool prefix_covers(std::string_view prefix, std::string_view path);

    /// The headers on the copy that goes upstream (README § Headers): Cookie
    /// off, hop-by-hop off,
    /// Authorization = Bearer @p at (none added when @p at is empty — the
    /// client had nothing, Basic/Session/Secret pass as they are), one
    /// X-Forwarded-For (the incoming one from nginx, else the peer), X-Forwarded-
    /// Proto https, X-Gateway-Worker, a fresh X-Request-Id (the client's, if
    /// any, moves to X-Client-Request-Id). Returns the X-Request-Id it set.
    std::string shape_upstream(HttpRequest& up, std::string_view at) const;
    /// The module's answer before it reaches the client: Set-Cookie of
    /// the module dropped (cookies are set by refresh only), X-Request-Id
    /// forced to ours.
    static void shape_downstream(HttpResponse& r, std::string_view request_id);
    void set_state(Instance& inst, std::string_view to, std::string_view reason);
    nlohmann::json table_json() const;

    // ── Mirror in gateway.node (README § Mirror) ───────────────────────────
    //
    // Every write goes through one FIFO per worker (mirror_queue_): the pool
    // has several connections and dispatches to any idle one, so two writes
    // sent back to back may reach the database in either order — an `offline`
    // from a dropped socket overtaken by the `ready` of the reconnect would
    // leave the row offline until the next reload. One outstanding write at
    // a time keeps the order the worker saw.

    /// Queue a mirror statement. @p on_result is called with the results of
    /// a successful run; a failure is logged (throttled) and dropped — the
    /// reload re-asserts what the database missed. @p kind non-empty
    /// marks a periodic write (seen, reload): a queued one of the same kind
    /// is replaced, not stacked — with the database away the queue would
    /// otherwise grow one per interval and replay the lot on reconnect.
    void mirror_exec(std::string sql, std::string what, PgQuery::ResultHandler on_result = {},
                     std::string kind = {});
    void mirror_next();
    /// Upsert the row from @p inst. @p pre_reason non-empty — first mark the
    /// existing row offline with that reason (register: the previous socket,
    /// wherever it was, is over), then write @p inst.state with @p reason.
    /// @p reassert — the row is written only if it is still ours or offline
    /// (another worker may have registered the instance since our snapshot),
    /// and `registered` is kept: a re-assert is not a registration.
    void mirror_upsert(const Instance& inst, std::string_view pre_reason, std::string_view reason,
                       bool reassert = false);
    /// UPDATE state (+ worker) with @p reason in the gateway.reason GUC.
    void mirror_state(const Instance& inst, std::string_view reason);
    /// `seen = now()` for the own instances that heartbeated within the last
    /// interval — one statement per worker per interval.
    void mirror_seen(std::chrono::system_clock::time_point now);
    /// Sweep (rows of OTHER workers with `seen` older than (offline_after + 1)
    /// intervals → offline) and re-read every non-offline row, in one
    /// transaction; then reconcile: own rows re-asserted, foreign rows
    /// mirrored, mirrored rows that are gone → offline.
    void mirror_reload();
    void mirror_apply(const nlohmann::json& row, std::string_view why);
    /// NOTIFY `gateway` — the trigger's payload {op, module, instance, state,
    /// state_from, address, prefixes, worker}. Own writes come back too.
    void on_gateway_notify(std::string_view payload);
    void on_gateway_notify_(std::string_view payload);
    void take_over(const std::string& module, const std::string& instance, int by_worker);
    static std::string sql_prefixes(const std::vector<std::string>& prefixes);
    static std::string sql_ident(std::string_view module, std::string_view instance);
    void mirror_warn(std::string_view what, std::string_view error);

    // ── Helpers ────────────────────────────────────────────────────────────

    static bool parse_control_path(std::string_view path, std::string_view control_path,
                                   std::string& module, std::string& instance,
                                   std::string& command);
    static bool valid_name(std::string_view s);
    static bool valid_prefix(std::string_view s);
    static bool parse_address(std::string_view address, std::string& host, uint16_t& port);
    bool address_allowed(const std::string& host) const;
    static std::string new_uuid();

    // ── State ──────────────────────────────────────────────────────────────

    EventLoop&            loop_;
    PgPool&               db_;            // worker pool (daemon) — the mirror lives in the project database
    bool                  enabled_{true};

    // module.GatewayAPI (README § Configuration)
    std::string control_path_{"/gateway"};
    int         heartbeat_interval_{5};
    int         suspect_after_{2};
    int         offline_after_{4};
    std::string audience_{"gateway"};
    int         connect_timeout_ms_{1000};
    int         response_timeout_ms_{30000};
    int         reload_interval_{60};
    struct Cidr { uint32_t net; uint32_t mask; };
    std::vector<Cidr> allowed_cidr_;

    static constexpr int         k_register_deadline_s = 5;
    static constexpr int         k_call_timeout_s      = 5;
    static constexpr std::size_t k_max_frame_bytes     = 64 * 1024;
    static constexpr int         k_close_grace_ms      = 1500;
    static constexpr int         k_passive_errors      = 5;      // connect failures → suspect

    std::unordered_map<int, std::shared_ptr<Node>> nodes_;          // by fd
    std::map<std::string, std::map<std::string, Instance>> table_;  // module → instance
    unsigned rr_{0};   // round-robin cursor for pick_instance ties
    std::map<std::string, Upstream> upstreams_;   // by "host:port"
    int pid_{0};

    // mirror
    bool listen_armed_{false};
    std::chrono::system_clock::time_point next_seen_{};
    std::chrono::system_clock::time_point next_reload_{};
    std::chrono::system_clock::time_point mirror_warned_{};
    struct MirrorWrite { std::string sql; std::string what; PgQuery::ResultHandler on_result; std::string kind; };
    std::deque<MirrorWrite> mirror_queue_;
    bool mirror_busy_{false};
    std::chrono::system_clock::time_point mirror_sent_{};   // when the outstanding write was sent
};

} // namespace apostol
