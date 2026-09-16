// GatewayAPI — control plane and routing table. See GatewayAPI.hpp.

#include "GatewayAPI.hpp"

#include "apostol/application.hpp"
#include "apostol/event_loop.hpp"
#include "apostol/http.hpp"
#include "apostol/http_utils.hpp"
#include "apostol/jwt.hpp"
#include "apostol/logger.hpp"
#include "apostol/oauth_providers.hpp"
#include "apostol/pg_utils.hpp"

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <algorithm>
#include <random>

#include <fmt/format.h>

namespace apostol {

using json = nlohmann::json;
using clock_t_ = std::chrono::system_clock;

namespace {

int seconds_since(clock_t_::time_point from, clock_t_::time_point now)
{
    return static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(now - from).count());
}

// Longest common rule for prefix overlap: equal, or one is a path-prefix of
// the other ("/api/v2/clients" vs "/api/v2/clients/vip"). "/api/v2/client"
// and "/api/v2/clients" do NOT overlap — the boundary is a '/'.
bool prefixes_overlap(std::string_view a, std::string_view b)
{
    if (a == b) return true;
    if (a.size() < b.size()) std::swap(a, b);
    return a.substr(0, b.size()) == b && a[b.size()] == '/';
}

// json::value() throws on a key whose value is null; gateway.node.worker is
// nullable and a row written by another application may leave it so.
int int_or(const nlohmann::json& o, const char* key, int def)
{
    auto it = o.find(key);
    return it != o.end() && it->is_number_integer() ? it->get<int>() : def;
}

} // namespace

// ─── ctor / config ───────────────────────────────────────────────────────────

GatewayAPI::GatewayAPI(Application& app)
    : AppServer(app)
    , loop_(app.worker_loop())
    , db_(app.db_pool())
    , pid_(static_cast<int>(::getpid()))
{
    add_allowed_header("Authorization");

    if (const auto* cfg = app.module_config("GatewayAPI")) {
        control_path_        = cfg->value("control_path", control_path_);
        connect_timeout_ms_  = cfg->value("connect_timeout_ms", connect_timeout_ms_);
        response_timeout_ms_ = cfg->value("response_timeout_ms", response_timeout_ms_);
        reload_interval_     = cfg->value("reload_interval", reload_interval_);
        heartbeat_interval_ = cfg->value("heartbeat_interval", heartbeat_interval_);
        suspect_after_      = cfg->value("suspect_after", suspect_after_);
        offline_after_      = cfg->value("offline_after", offline_after_);
        audience_           = cfg->value("audience", audience_);

        if (cfg->contains("allowed_cidr") && (*cfg)["allowed_cidr"].is_array()) {
            for (const auto& item : (*cfg)["allowed_cidr"]) {
                if (!item.is_string()) continue;
                const std::string s = item.get<std::string>();
                auto slash = s.find('/');
                std::string ip   = s.substr(0, slash);
                // No std::stoi: a typo like "10.0.0.0/" or "/xx" would throw
                // out of the constructor and take the worker down at start.
                int bits = 32;
                if (slash != std::string::npos) {
                    bits = 0;
                    std::string_view digits = std::string_view(s).substr(slash + 1);
                    if (digits.empty() || digits.size() > 2) bits = -1;
                    for (char c : digits) {
                        if (c < '0' || c > '9') { bits = -1; break; }
                        bits = bits * 10 + (c - '0');
                    }
                }
                in_addr a{};
                if (bits < 0 || bits > 32 || ::inet_pton(AF_INET, ip.c_str(), &a) != 1) {
                    log_.warn("GatewayAPI: allowed_cidr entry '{}' ignored (IPv4 a.b.c.d/n only)", s);
                    continue;
                }
                uint32_t mask = bits == 0 ? 0u : (0xFFFFFFFFu << (32 - bits));
                allowed_cidr_.push_back({ntohl(a.s_addr) & mask, mask});
            }
        }
    }

    // A control path without a leading slash or with a trailing one would
    // never match parse_control_path; normalise once here.
    if (control_path_.empty() || control_path_[0] != '/') control_path_ = "/" + control_path_;
    while (control_path_.size() > 1 && control_path_.back() == '/') control_path_.pop_back();

    if (heartbeat_interval_ < 1) heartbeat_interval_ = 1;
    if (suspect_after_ < 1)      suspect_after_ = 1;
    if (offline_after_ <= suspect_after_) offline_after_ = suspect_after_ + 1;
    if (reload_interval_ < 1)    reload_interval_ = 1;

    if (allowed_cidr_.empty())
        log_.warn("GatewayAPI: allowed_cidr is empty — every /register will be refused with 403");

    // The audience is a provider of oauth2/*.json — by default `service`, the
    // client_credentials client every deployment has already. Providers are
    // loaded in load_config() before on_worker_start(), so this reads the
    // final set.
    // Nothing here fails open: verify_jwt throws on an empty secret and
    // check_gateway_token answers "unauthorized" to an unknown audience — but
    // an image shipped without the secret would then refuse every module with
    // nothing in the log but their close reasons. Say it once, at start.
    if (const auto* aud_app = providers_.find_default(audience_); !aud_app)
        log_.error("GatewayAPI: audience '{}' is not in oauth2/*.json — every module will be refused (unauthorized)",
                   audience_);
    else if (aud_app->client_secret.empty())
        log_.error("GatewayAPI: audience '{}' ({}) has an empty client_secret — every module will be refused (unauthorized)",
                   audience_, aud_app->client_id);

    log_.notice("GatewayAPI: control_path={} heartbeat_interval={}s suspect_after={} offline_after={} audience={} cidr={}",
                control_path_, heartbeat_interval_, suspect_after_, offline_after_, audience_,
                allowed_cidr_.size());
}

void GatewayAPI::init_methods()
{
    add_method("GET",    [this](const HttpRequest& r, HttpResponse& s) { do_get(r, s); });
    add_method("POST",   [this](const HttpRequest& r, HttpResponse& s) { do_post(r, s); });
    add_method("PUT",    [this](const HttpRequest& r, HttpResponse& s) { do_put(r, s); });
    add_method("PATCH",  [this](const HttpRequest& r, HttpResponse& s) { do_patch(r, s); });
    add_method("DELETE", [this](const HttpRequest& r, HttpResponse& s) { do_delete(r, s); });
}

// ─── location ────────────────────────────────────────────────────────────────

bool GatewayAPI::check_location(const HttpRequest& req) const
{
    // Control path (/gateway/*) and the data plane (/api/v2/*, fixed: every
    // prefix is ^/api/v2/…). Registered before AppServer, so first-match-wins
    // keeps /api/v1/* there.
    return req.path == control_path_ ||
           (req.path.size() > control_path_.size() &&
            req.path.compare(0, control_path_.size(), control_path_) == 0 &&
            req.path[control_path_.size()] == '/') ||
           is_data_path(req.path);
}

bool GatewayAPI::is_data_path(std::string_view path) const
{
    return path.starts_with("/api/v2/");
}

bool GatewayAPI::owns_ws_upgrade(const HttpRequest& req) const
{
    return enabled_ && check_location(req);
}

// ─── path helpers ────────────────────────────────────────────────────────────

bool GatewayAPI::parse_control_path(std::string_view path, std::string_view control_path,
                                    std::string& module, std::string& instance,
                                    std::string& command)
{
    module.clear(); instance.clear(); command.clear();
    if (path.size() <= control_path.size() || path.substr(0, control_path.size()) != control_path ||
        path[control_path.size()] != '/')
        return false;

    std::string_view rest = path.substr(control_path.size() + 1);
    std::vector<std::string_view> seg;
    while (!rest.empty()) {
        auto pos = rest.find('/');
        seg.push_back(rest.substr(0, pos));
        if (pos == std::string_view::npos) break;
        rest = rest.substr(pos + 1);
    }
    if (seg.empty() || seg.size() > 3) return false;
    if (seg.size() == 1) { command = std::string(seg[0]); return true; }   // /gateway/list
    module   = std::string(seg[0]);
    instance = std::string(seg[1]);
    if (seg.size() == 3) command = std::string(seg[2]);
    return true;
}

bool GatewayAPI::valid_name(std::string_view s)
{
    // ^[a-z0-9][a-z0-9_-]{0,62}$ (README § Handshake)
    if (s.empty() || s.size() > 63) return false;
    auto ok_first = [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); };
    if (!ok_first(s[0])) return false;
    return std::all_of(s.begin() + 1, s.end(),
                       [&](char c) { return ok_first(c) || c == '_' || c == '-'; });
}

bool GatewayAPI::valid_prefix(std::string_view s)
{
    // ^/api/v2/[a-z0-9_/-]+$ without '*' and without a trailing '/' (README § /register)
    static constexpr std::string_view head = "/api/v2/";
    if (s.size() <= head.size() || s.substr(0, head.size()) != head) return false;
    if (s.back() == '/') return false;
    return std::all_of(s.begin() + static_cast<long>(head.size()), s.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '/';
    });
}

bool GatewayAPI::parse_address(std::string_view address, std::string& host, uint16_t& port)
{
    auto colon = address.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 >= address.size()) return false;
    host = std::string(address.substr(0, colon));
    in_addr a{};
    if (::inet_pton(AF_INET, host.c_str(), &a) != 1) return false;   // IPv4 literal only
    int p = 0;
    for (char c : address.substr(colon + 1)) {
        if (c < '0' || c > '9') return false;
        p = p * 10 + (c - '0');
        if (p > 65535) return false;
    }
    if (p == 0) return false;
    port = static_cast<uint16_t>(p);
    return true;
}

bool GatewayAPI::address_allowed(const std::string& host) const
{
    in_addr a{};
    if (::inet_pton(AF_INET, host.c_str(), &a) != 1) return false;
    const uint32_t ip = ntohl(a.s_addr);
    return std::any_of(allowed_cidr_.begin(), allowed_cidr_.end(),
                       [ip](const Cidr& c) { return (ip & c.mask) == c.net; });
}

std::string GatewayAPI::new_uuid()
{
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    uint64_t a = rng(), b = rng();
    a = (a & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;   // version 4
    b = (b & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;   // variant 10
    return fmt::format("{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                       static_cast<uint32_t>(a >> 32), static_cast<uint16_t>(a >> 16),
                       static_cast<uint16_t>(a), static_cast<uint16_t>(b >> 48),
                       b & 0xFFFFFFFFFFFFULL);
}

// ─── token ───────────────────────────────────────────────────────────────────

std::string GatewayAPI::check_gateway_token(const HttpRequest& req) const
{
    auto auth = parse_authorization(req.header("Authorization"));
    if (auth.schema != Authorization::Schema::bearer || auth.token.empty())
        return "unauthorized";
    try {
        auto claims = verify_jwt(auth.token, providers_);
        // verify_jwt found SOME provider by aud and checked the signature with
        // its secret. That is not enough: a valid web/service token must not
        // open the control plane. The aud has to be THIS audience's client_id.
        const auto* app = providers_.find_default(audience_);
        if (!app || claims.aud != app->client_id)
            return "unauthorized";
        return {};
    } catch (const JwtExpiredError&) {
        return "forbidden";
    } catch (const std::exception&) {
        // JwtVerificationError — and anything else verify_jwt lets out on a
        // string that is not a token at all (base64 "too much fill" from a
        // garbage Bearer, measured with the stub). Same answer either way.
        return "unauthorized";
    }
}

void GatewayAPI::reply_problem(HttpResponse& resp, int status, std::string_view slug,
                               std::string_view title, std::string_view detail,
                               std::string_view instance_path, std::string_view request_id) const
{
    const std::string rid = request_id.empty() ? new_uuid() : std::string(request_id);
    json body = {
        {"type",       fmt::format("urn:apostol:gateway:{}", slug)},
        {"title",      title},
        {"status",     status},
        {"detail",     detail},
        {"instance",   instance_path},
        {"request_id", rid},
        {"code",       nullptr},
    };
    resp.set_status(status, std::string(title));
    resp.set_header("X-Request-Id", rid);
    resp.set_body(body.dump(), "application/problem+json");
}

// ─── HTTP: list and commands ─────────────────────────────────────────────────

void GatewayAPI::do_get(const HttpRequest& req, HttpResponse& resp)
{
    if (is_data_path(req.path)) { data_plane(req, resp, "GET"); return; }
    std::string module, instance, command;
    if (!parse_control_path(req.path, control_path_, module, instance, command) ||
        !module.empty() || (command != "list" && command != "route")) {
        reply_problem(resp, 404, "no-route", "Not Found", "unknown control path", req.path);
        return;
    }
    if (auto why = check_gateway_token(req); !why.empty()) {
        reply_problem(resp, why == "forbidden" ? 403 : 401,
                      why == "forbidden" ? "token-expired" : "token-invalid",
                      why == "forbidden" ? "Forbidden" : "Unauthorized",
                      "gateway audience token required", req.path);
        return;
    }
    if (command == "route") {
        // GET /gateway/route?path=/api/v2/… — "where would this path go from
        // THIS worker right now". The same resolution the data plane runs, with
        // the same 404/503 problem+json, so the table can be measured before
        // and without a data-plane request. It moves the round-robin cursor
        // like a real request would.
        const auto path = req.param("path");
        if (!path.starts_with("/api/v2/")) {
            reply_problem(resp, 400, "bad-request", "Bad Request", "path must start with /api/v2/", req.path);
            return;
        }
        bool covered = false;
        const auto* inst = pick_instance(path, {}, covered);
        if (!inst) {
            if (covered) {
                reply_problem(resp, 503, "no-instance", "Service Unavailable", "route exists, no instance is ready", path);
                resp.set_header("Retry-After", "1");
            } else {
                reply_problem(resp, 404, "no-route", "Not Found", "no prefix covers the path", path);
            }
            return;
        }
        json out = {
            {"gateway_worker", pid_},
            {"path",     path},
            {"module",   inst->module},
            {"instance", inst->instance},
            {"address",  inst->address},
            {"local_in_flight", inst->in_flight},
        };
        resp.set_status(200, "OK").set_body(out.dump(), "application/json");
        return;
    }
    json out = {
        {"gateway_worker", pid_},
        {"heartbeat_interval", heartbeat_interval_},
        {"suspect_after", suspect_after_},
        {"offline_after", offline_after_},
        {"instances", table_json()},
    };
    resp.set_status(200, "OK").set_body(out.dump(), "application/json");
}

void GatewayAPI::do_post(const HttpRequest& req, HttpResponse& resp)
{
    if (is_data_path(req.path)) { data_plane(req, resp, "POST"); return; }
    std::string module, instance, command;
    if (!parse_control_path(req.path, control_path_, module, instance, command) ||
        module.empty() || (command != "ping" && command != "drain" && command != "reload")) {
        reply_problem(resp, 404, "no-route", "Not Found", "unknown control path", req.path);
        return;
    }
    if (auto why = check_gateway_token(req); !why.empty()) {
        reply_problem(resp, why == "forbidden" ? 403 : 401,
                      why == "forbidden" ? "token-expired" : "token-invalid",
                      why == "forbidden" ? "Forbidden" : "Unauthorized",
                      "gateway audience token required", req.path);
        return;
    }

    // Only the worker holding the socket can talk to the module. A command
    // that lands on another worker answers 409 — the caller retries and nginx
    // spreads it; the mirror says which worker holds it.
    std::shared_ptr<Node> target = socket_of(module, instance);
    if (!target) {
        // The mirror knows who holds it: the caller retries and nginx spreads
        // it; the owner pid is in the detail for a reader, not for routing.
        const auto* known = find_instance(module, instance);
        reply_problem(resp, 409, "not-on-this-worker", "Conflict",
                      known && known->source == Source::mirror
                          ? fmt::format("instance {}/{} holds no socket on worker {}; owner worker {}",
                                        module, instance, pid_, known->owner_worker)
                          : fmt::format("instance {}/{} holds no socket on worker {}", module, instance, pid_),
                      req.path);
        return;
    }

    json p = json::object();
    if (!req.body.empty()) {
        p = json::parse(req.body, nullptr, false);
        if (!p.is_object()) {
            reply_problem(resp, 400, "bad-request", "Bad Request", "body must be a JSON object", req.path);
            return;
        }
    }

    resp.set_deferred(true);
    send_call(target, "/" + command, p, req.connection_ctx);
}

// ─── WebSocket: upgrade, epoll, teardown ─────────────────────────────────────

std::string GatewayAPI::handshake_refusal(const HttpRequest& req, std::string& module, std::string& instance) const
{
    std::string command;
    if (!parse_control_path(req.path, control_path_, module, instance, command) ||
        module.empty() || !command.empty())
        return "not-found";
    if (!valid_name(module) || !valid_name(instance))
        return "bad-request";
    return check_gateway_token(req);   // "" | "unauthorized" | "forbidden"
}

bool GatewayAPI::ws_upgrade_allowed(const HttpRequest& req, HttpResponse& resp) const
{
    std::string module, instance;
    const auto refuse = handshake_refusal(req, module, instance);
    if (refuse.empty()) return true;

    // The refusal is an HTTP status before the 101, problem+json like
    // every other answer of the gateway. The module sees it on dial.
    if (refuse == "not-found")
        reply_problem(resp, 404, "not-found", "Not Found", "unknown control path", req.path);
    else if (refuse == "bad-request")
        reply_problem(resp, 400, "bad-request", "Bad Request", "module and instance: ^[a-z0-9][a-z0-9_-]{0,62}$", req.path);
    else if (refuse == "forbidden")
        reply_problem(resp, 403, "token-expired", "Forbidden", "gateway audience token expired", req.path);
    else
        reply_problem(resp, 401, "token-invalid", "Unauthorized", "gateway audience token required", req.path);
    log_.warn("GatewayAPI: upgrade {} from {} refused before 101 ({})", req.path, get_real_ip(req), refuse);
    return false;
}

void GatewayAPI::on_ws_upgrade(EventLoop& loop, WsConnection ws, const HttpRequest& req)
{
    std::string module, instance;
    const auto refuse = handshake_refusal(req, module, instance);   // same predicate as the filter

    // Even a refused socket gets a node and an epoll slot: the close frame
    // must be followed by the peer's close (or a grace period) before the
    // TCP socket is closed, or close() with unread bytes turns into an RST
    // and the peer never sees our code and reason. Measured with the stub:
    // an immediate close() after send_close() lost the reason one time in
    // two and the whole frame the other.
    auto node = add_node(std::move(ws), std::move(module), std::move(instance), get_real_ip(req));
    const int fd = node->ws->fd();
    node->ws->bind_event_loop(loop);

    // Same shape as WebSocketAPI::on_ws_upgrade: the fd is already in epoll
    // from the HTTP accept loop; replace the handler.
    loop.remove_io(fd);
    loop.add_io(fd, EPOLLIN, [this, node](uint32_t events) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            drop_node(node);
            return;
        }
        if (events & EPOLLIN) {
            bool ok = node->ws->on_readable(
                [this, node](uint8_t opcode, const std::string& payload) {
                    on_ws_message(node, opcode, payload);
                },
                [this, node]() { drop_node(node); });
            if (!ok) {
                drop_node(node);
                return;
            }
        }
        if (events & EPOLLOUT) {
            node->ws->on_writable();
            if (node->ws->closed()) {
                drop_node(node);
                return;
            }
        }
        uint32_t mask = EPOLLIN;
        if (node->ws->has_pending_writes())
            mask |= EPOLLOUT;
        loop_.rearm_io(node->ws->fd(), mask);
    });

    if (!refuse.empty()) {
        // Normally unreachable: ws_upgrade_allowed() refused this before the
        // 101 (the application installs it as the upgrade filter).
        // Kept as the fallback for a build without the filter: close 1008
        // with the reason is then what the module sees.
        log_.warn("GatewayAPI: {}/{} from {}: handshake refused ({})", node->module, node->instance,
                  node->peer_ip, refuse);
        close_node(node, 1008, refuse);
        return;
    }

    log_.notice("GatewayAPI: {}/{} connected from {} (fd={})", node->module, node->instance,
                node->peer_ip, fd);
}

std::shared_ptr<GatewayAPI::Node> GatewayAPI::add_node(WsConnection ws, std::string module,
                                                       std::string instance, std::string peer_ip)
{
    auto node = std::make_shared<Node>();
    node->ws        = std::make_shared<WsConnection>(std::move(ws));
    node->module    = std::move(module);
    node->instance  = std::move(instance);
    // The listener is dual-stack: an IPv4 peer arrives as "::ffff:a.b.c.d".
    if (peer_ip.rfind("::ffff:", 0) == 0) peer_ip.erase(0, 7);
    node->peer_ip   = std::move(peer_ip);
    node->connected = clock_t_::now();
    nodes_[node->ws->fd()] = node;
    return node;
}

void GatewayAPI::close_node(const std::shared_ptr<Node>& node, uint16_t code, std::string_view reason)
{
    if (node->closing) return;
    node->closing = true;
    node->ws->send_close(code, reason);
    // Any HTTP caller waiting on this node gets 502 now.
    for (auto& [u, call] : node->pending) {
        if (call.http_conn) {
            HttpResponse r;
            reply_problem(r, 502, "upstream-error", "Bad Gateway",
                          fmt::format("socket closed ({}) before {} was answered", reason, call.action),
                          control_path_);
            std::static_pointer_cast<HttpConnection>(call.http_conn)->send_response(r);
        }
    }
    node->pending.clear();
    // Closing handshake (RFC 6455 §7.1.2): the socket stays in epoll until
    // the peer answers with its own close frame — on_readable then returns
    // false and drop_node runs — or until the grace deadline in heartbeat()
    // for a peer that never answers.
    node->close_deadline = clock_t_::now() + std::chrono::milliseconds(k_close_grace_ms);
}

void GatewayAPI::drop_node(const std::shared_ptr<Node>& node)
{
    const int fd = node->ws->fd();
    auto it = nodes_.find(fd);
    if (it == nodes_.end() || it->second != node) return;   // already gone, or fd reused
    nodes_.erase(it);
    loop_.remove_io(fd);

    for (auto& [u, call] : node->pending) {
        if (call.http_conn) {
            HttpResponse r;
            reply_problem(r, 502, "upstream-error", "Bad Gateway",
                          fmt::format("socket closed before {} was answered", call.action),
                          control_path_);
            std::static_pointer_cast<HttpConnection>(call.http_conn)->send_response(r);
        }
    }
    node->pending.clear();

    // A close WE started (unregister, heartbeat timeout, replacement) wrote
    // the state before calling close_node; only a close the PEER started
    // (EOF, reset, protocol error) is recorded here. A replaced node has
    // registered=false, so it never touches the row now owned by its successor.
    if (node->registered && !node->closing)
        if (auto* inst = find_instance(node->module, node->instance);
            inst && inst->source == Source::socket && inst->owner_worker == pid_)
            set_state(*inst, "offline", "socket closed");
    log_.notice("GatewayAPI: {}/{} disconnected (fd={})", node->module, node->instance, fd);
    // `node` and its WsConnection die here: TcpConnection closes the fd.
}

// ─── WebSocket: frames ───────────────────────────────────────────────────────

void GatewayAPI::send_call_result(WsConnection& ws, std::string_view u, const json& p)
{
    json msg = {{"t", 3}, {"u", u}, {"p", p}};
    ws.send_text(msg.dump());
}

void GatewayAPI::send_call_error(WsConnection& ws, std::string_view u, int code, std::string_view message)
{
    json msg = {{"t", 4}, {"u", u}, {"c", code}, {"m", message}};
    ws.send_text(msg.dump());
}

void GatewayAPI::send_call(const std::shared_ptr<Node>& node, std::string_view action,
                           const json& p, std::shared_ptr<void> http_conn)
{
    const std::string u = new_uuid();
    node->pending[u] = PendingCall{std::string(action), clock_t_::now(), std::move(http_conn)};
    json msg = {{"t", 2}, {"u", u}, {"a", action}, {"p", p}};
    node->ws->send_text(msg.dump());
}

void GatewayAPI::on_ws_message(const std::shared_ptr<Node>& node, uint8_t opcode, const std::string& payload)
{
    if (node->closing) return;

    if (opcode == WS_OP_BINARY) {
        close_node(node, 1003, "binary frame");
        return;
    }
    if (opcode != WS_OP_TEXT) return;   // ping/pong handled by WsConnection
    if (payload.size() > k_max_frame_bytes) {
        close_node(node, 1009, "frame too big");
        return;
    }

    json msg = json::parse(payload, nullptr, false);
    if (!msg.is_object()) {
        send_call_error(*node->ws, "", 400, "frame is not a JSON object");
        return;
    }
    const int t = msg.value("t", -1);
    std::string u;
    if (msg.contains("u") && msg["u"].is_string()) u = msg["u"].get<std::string>();

    switch (t) {
        case 2: {
            if (u.empty()) { send_call_error(*node->ws, "", 400, "missing u"); return; }
            // "duplicate u in flight" cannot happen here: every CALL is
            // answered synchronously inside this callback, so nothing from
            // the module is ever in flight when the next frame is parsed.
            std::string action = msg.value("a", "");
            json p = msg.contains("p") ? msg["p"] : json::object();
            if (!p.is_object()) {
                send_call_error(*node->ws, u, 400, "p must be an object");
                return;
            }
            on_call(node, u, action, p);
            return;
        }
        case 3:
        case 4:
            on_reply(node, msg);
            return;
        case 0:
        case 1:
            send_call_error(*node->ws, u, 400, "OPEN/CLOSE are not used on the control plane");
            return;
        default:
            send_call_error(*node->ws, u, 400, "unknown message type");
            return;
    }
}

void GatewayAPI::on_call(const std::shared_ptr<Node>& node, const std::string& u,
                         const std::string& action, const json& p)
{
    if (action == "/register")   { handle_register(node, u, p);   return; }
    if (!node->registered) {
        send_call_error(*node->ws, u, 409, "not registered");
        return;
    }
    if (action == "/heartbeat")  { handle_heartbeat(node, u, p);  return; }
    if (action == "/status")     { handle_status(node, u, p);     return; }
    if (action == "/unregister") { handle_unregister(node, u, p); return; }
    send_call_error(*node->ws, u, 404, fmt::format("unknown action {}", action));
}

void GatewayAPI::on_reply(const std::shared_ptr<Node>& node, const json& msg)
{
    std::string u = msg.value("u", "");
    auto it = node->pending.find(u);
    if (it == node->pending.end()) {
        log_.debug("GatewayAPI: {}/{}: reply to unknown u={}", node->module, node->instance, u);
        return;
    }
    PendingCall call = std::move(it->second);
    node->pending.erase(it);

    const int t = msg.value("t", -1);
    log_.debug("GatewayAPI: {}/{}: {} answered ({}) in {} ms", node->module, node->instance,
               call.action, t == 3 ? "result" : "error",
               std::chrono::duration_cast<std::chrono::milliseconds>(clock_t_::now() - call.sent).count());

    if (call.http_conn) {
        HttpResponse r;
        if (t == 3) {
            json p = msg.contains("p") ? msg["p"] : json::object();
            r.set_status(200, "OK").set_body(p.dump(), "application/json");
        } else {
            reply_problem(r, 502, "upstream-error", "Bad Gateway",
                          fmt::format("module answered {} with {}: {}", call.action,
                                      msg.value("c", 0), msg.value("m", "")),
                          control_path_);
        }
        std::static_pointer_cast<HttpConnection>(call.http_conn)->send_response(r);
    }
}

// ─── actions ─────────────────────────────────────────────────────────────────

void GatewayAPI::handle_register(const std::shared_ptr<Node>& node, const std::string& u, const json& p)
{
    if (node->registered) {
        send_call_error(*node->ws, u, 409, "already registered on this socket");
        return;
    }
    auto fail = [&](int code, std::string_view why) {
        log_.warn("GatewayAPI: {}/{} from {}: /register refused {} ({})", node->module,
                  node->instance, node->peer_ip, code, why);
        send_call_error(*node->ws, u, code, why);
        close_node(node, 1008, why);
    };

    // 400 — shape
    for (const char* key : {"module", "instance", "version", "address"})
        if (!p.contains(key) || !p[key].is_string()) { fail(400, fmt::format("missing or non-string {}", key)); return; }
    if (!p.contains("prefixes") || !p["prefixes"].is_array() || p["prefixes"].empty()) { fail(400, "prefixes must be a non-empty array"); return; }
    if (!p.contains("capacity") || !p["capacity"].is_number_integer()) { fail(400, "capacity must be an integer"); return; }
    if (p.contains("build") && !p["build"].is_string()) { fail(400, "build must be a string"); return; }

    // 422 — content
    if (p["module"].get<std::string>() != node->module || p["instance"].get<std::string>() != node->instance) {
        fail(422, "module/instance differ from the URL"); return;
    }
    const int capacity = p["capacity"].get<int>();
    if (capacity < 1) { fail(422, "capacity < 1"); return; }

    std::vector<std::string> prefixes;
    for (const auto& item : p["prefixes"]) {
        if (!item.is_string()) { fail(400, "prefix must be a string"); return; }
        const auto s = item.get<std::string>();
        if (!valid_prefix(s)) { fail(400, fmt::format("bad prefix {}", s)); return; }
        for (const auto& have : prefixes)
            if (prefixes_overlap(have, s)) { fail(422, fmt::format("prefixes overlap: {} and {}", have, s)); return; }
        prefixes.push_back(s);
    }

    std::string host; uint16_t port = 0;
    if (!parse_address(p["address"].get<std::string>(), host, port)) { fail(400, "address must be ipv4:port"); return; }

    // 403 — network
    if (!address_allowed(host)) { fail(403, fmt::format("address {} is outside allowed_cidr", host)); return; }
    if (host != node->peer_ip)
        log_.warn("GatewayAPI: {}/{}: address {} differs from socket peer {} (allowed)",
                  node->module, node->instance, host, node->peer_ip);

    // 409 — a prefix owned by ANOTHER module
    for (const auto& [mod, insts] : table_) {
        if (mod == node->module) continue;
        for (const auto& [name, inst] : insts) {
            if (inst.state == "offline") continue;
            for (const auto& theirs : inst.prefixes)
                for (const auto& mine : prefixes)
                    if (prefixes_overlap(theirs, mine)) {
                        fail(409, fmt::format("prefix {} belongs to module {}", mine, mod)); return;
                    }
        }
    }

    // Replacement (README § Handshake): a live socket for the same instance is
    // displaced — closed 1001, its table row re-pointed at this node.
    bool replaced = false;
    for (auto& [fd, other] : nodes_) {
        if (other == node || !other->registered || other->closing) continue;
        if (other->module == node->module && other->instance == node->instance) {
            log_.notice("GatewayAPI: {}/{}: replaced — closing previous socket fd={}", node->module,
                        node->instance, fd);
            other->registered = false;   // drop_node must not mark the row offline
            close_node(other, 1001, "replaced");
            replaced = true;
        }
    }

    const auto now = clock_t_::now();
    Instance& inst = table_[node->module][node->instance];
    const bool existed = !inst.module.empty();
    const std::string from = existed ? inst.state : "(none)";
    inst.module    = node->module;
    inst.instance  = node->instance;
    inst.version   = p["version"].get<std::string>();
    inst.build     = p.value("build", "");
    inst.address   = p["address"].get<std::string>();
    inst.host      = host;
    inst.port      = port;
    inst.prefixes  = std::move(prefixes);
    inst.capacity  = capacity;
    inst.state     = "ready";
    inst.reported_in_flight = 0;
    inst.load      = 0.0;
    inst.conn_errors = 0;
    inst.registered = now;
    inst.last_heartbeat = now;
    inst.owner_worker = pid_;
    inst.source    = Source::socket;

    node->registered = true;
    log_.notice("GatewayAPI: {}/{} {} -> ready (register: {} v{} prefixes={} capacity={})",
                node->module, node->instance, from, inst.address, inst.version,
                inst.prefixes.size(), inst.capacity);
    // The row is (re)written by the socket's owner. Whatever the row said
    // before — a socket displaced here, a socket on a worker that died, a
    // previous life of this very worker — that registration is over: it is
    // closed in the journal first, so gateway.log never shows ready → ready
    // with a new address and the other workers get an offline they can act
    // on before the ready that re-points them (the trigger is silent on an
    // UPDATE that keeps the state).
    mirror_upsert(inst, replaced ? "replaced" : "re-registered", "registered");

    send_call_result(*node->ws, u, {
        {"heartbeat_interval", heartbeat_interval_},
        {"instance_id",        node->instance},
        {"gateway_worker",     pid_},
        {"suspect_after",      suspect_after_},
        {"offline_after",      offline_after_},
    });
}

void GatewayAPI::handle_heartbeat(const std::shared_ptr<Node>& node, const std::string& u, const json& p)
{
    if (!p.contains("in_flight") || !p["in_flight"].is_number_integer() || p["in_flight"].get<int>() < 0) {
        send_call_error(*node->ws, u, 400, "in_flight must be a non-negative integer");
        return;
    }
    auto* inst = find_instance(node->module, node->instance);
    if (!inst) { send_call_error(*node->ws, u, 409, "not registered"); return; }

    const auto now = clock_t_::now();
    // 429 — faster than heartbeat_interval/2 (README § /heartbeat), measured against
    // the previous ACCEPTED heartbeat so a burst cannot ratchet the window.
    // The first heartbeat after /register is always accepted: last_heartbeat
    // still equals `registered` then.
    const auto since_last = std::chrono::duration_cast<std::chrono::milliseconds>(now - inst->last_heartbeat).count();
    if (inst->last_heartbeat != inst->registered && since_last < heartbeat_interval_ * 500) {
        send_call_error(*node->ws, u, 429, "heartbeat too frequent");
        return;
    }

    inst->last_heartbeat = now;
    inst->reported_in_flight = p["in_flight"].get<int>();
    if (p.contains("load") && p["load"].is_number()) inst->load = p["load"].get<double>();
    inst->conn_errors = 0;   // the passive counter resets on a heartbeat as on a good answer
    if (inst->state == "suspect")
        set_state(*inst, "ready", "heartbeat");

    send_call_result(*node->ws, u, {{"state", inst->state}});
}

void GatewayAPI::handle_status(const std::shared_ptr<Node>& node, const std::string& u, const json& p)
{
    const std::string state = p.value("state", "");
    if (state != "ready" && state != "draining" && state != "overloaded") {
        send_call_error(*node->ws, u, 422, "state must be ready|draining|overloaded");
        return;
    }
    auto* inst = find_instance(node->module, node->instance);
    if (!inst) { send_call_error(*node->ws, u, 409, "not registered"); return; }

    if (inst->state == "draining" && state != "draining") {
        // draining is irreversible within one socket (README § /status).
        send_call_error(*node->ws, u, 409, "draining is irreversible; unregister and register again");
        return;
    }
    if (inst->state != state)
        set_state(*inst, state, fmt::format("status{}", p.contains("reason") && p["reason"].is_string()
                                                        ? ": " + p["reason"].get<std::string>() : ""));
    send_call_result(*node->ws, u, json::object());
}

void GatewayAPI::handle_unregister(const std::shared_ptr<Node>& node, const std::string& u, const json& p)
{
    const std::string reason = p.value("reason", "");
    if (auto* inst = find_instance(node->module, node->instance))
        set_state(*inst, "offline", fmt::format("unregister: {}", reason));
    send_call_result(*node->ws, u, json::object());
    close_node(node, 1000, "unregistered");
}

// ─── data plane (README § Data plane) ──────────────────────────────────────────────────────

void GatewayAPI::data_plane(const HttpRequest& req, HttpResponse& resp, std::string_view method)
{
    if (!is_data_path(req.path)) {
        // PUT/PATCH/DELETE on the control path: the control plane knows GET
        // (list, route) and POST (commands) only. Without this the request
        // fell through to routing and came back as a misleading 404 no-route.
        resp.set_header("Allow", "GET, POST");
        reply_problem(resp, 405, "method-not-allowed", "Method Not Allowed",
                      fmt::format("{} is not a control-plane method", method), req.path);
        return;
    }
    // AppServer::do_fetch: shaping params, payload, check_auth (Bearer,
    // cookie AT, refresh with RT) → execute() below. What comes back
    // synchronously is a refusal: check_auth's 401/403 as AppServer's JSON
    // error — /api/v2/* answers problem+json, so rewrite it.
    do_fetch(req, resp, method);
    if (resp.is_deferred()) return;
    // Refusals of check_auth are problem+json already (reply_refused below).
    // What is left is the 400 of ResultShaping (result_object / result_format
    // — v1 knobs, meaningless here) or of a payload transformer: same shape
    // for every /api/v2/* answer.
    if (resp.status_code() == 400)
        reply_problem(resp, 400, "bad-request", "Bad Request", "request refused before routing", req.path);
}

void GatewayAPI::reply_refused(HttpResponse& resp, const Refusal& refusal)
{
    using Kind = Refusal::Kind;
    const int status = static_cast<int>(refusal.status);
    // An expired token and a refresh that cannot happen are one answer,
    // 401 token-expired (RFC 6750 §3.1); a token that never verified
    // is 401 token-invalid. The database's own refusal of the refresh
    // (ERR-401-…) is a refresh that cannot happen; any other status it gives
    // passes through with its own slug. The v1 bodies (challenge, {"error":…},
    // the database payload verbatim) do not reach /api/v2/* — the module side
    // speaks problem+json and so does the gateway.
    std::string_view slug, title;
    switch (refusal.kind) {
        case Kind::invalid:        slug = "token-invalid"; title = "Unauthorized"; break;
        case Kind::expired:
        case Kind::refresh_failed: slug = "token-expired"; title = "Unauthorized"; break;
        case Kind::database:
            slug  = status == 401 ? "token-expired" : "refresh-refused";
            title = status == 401 ? "Unauthorized" : "Refresh Refused";
            break;
        case Kind::internal:       slug = "internal";      title = "Internal Server Error"; break;
    }
    reply_problem(resp, status, slug, title, refusal.message, refusal.path);
}

void GatewayAPI::execute(const HttpRequest& req, std::shared_ptr<HttpConnection> conn,
                         const ExecContext& ctx, std::string_view /*method*/,
                         const std::string& /*payload*/, const ResultShaping& /*shaping*/)
{
    // The access token that goes upstream: the Bearer the client sent (already
    // verified by check_auth), the cookie AT, or the NEW one after a refresh.
    // Basic / Session / Secret headers pass as they are (shape_upstream keeps
    // the incoming Authorization when `at` is empty) — v2 modules answer 401.
    const std::string at = (ctx.auth_type == AuthType::bearer || ctx.refreshed) ? ctx.auth.token : std::string{};

    HttpRequest up = req;
    auto request_id = shape_upstream(up, at);

    bool covered = false;
    auto* inst = pick_instance(req.path, {}, covered);
    if (!inst) {
        if (covered)
            answer_problem(conn, ctx, 503, "no-instance", "Service Unavailable", "route exists, no instance is ready", req.path, request_id, /*retry_after=*/true);
        else
            answer_problem(conn, ctx, 404, "no-route", "Not Found", "no prefix covers the path", req.path, request_id);
        return;
    }
    forward_to(*inst, std::move(up), std::move(conn), ctx, std::move(request_id), 1);
}

GatewayAPI::Upstream& GatewayAPI::upstream_for(const Instance& inst)
{
    auto it = upstreams_.find(inst.address);
    if (it == upstreams_.end()) {
        Upstream u;
        u.proxy = std::make_unique<HttpProxy>(loop_, inst.host, inst.port);
        u.proxy->set_connect_timeout(std::chrono::milliseconds(connect_timeout_ms_));
        // Deadline on the whole answer (response_timeout_ms from send to last byte); the
        // idle bound follows it inside HttpProxy (raised to at least this).
        u.proxy->set_response_timeout(std::chrono::milliseconds(response_timeout_ms_));
        // Exactly one X-Forwarded-For — the one shape_upstream put there.
        u.proxy->set_append_forwarded_for(false);
        it = upstreams_.emplace(inst.address, std::move(u)).first;
    }
    return it->second;
}

void GatewayAPI::forward_to(Instance& inst, HttpRequest up, std::shared_ptr<HttpConnection> conn,
                            const ExecContext& ctx, std::string request_id, int attempt)
{
    auto& upstream = upstream_for(inst);
    ++inst.in_flight;
    ++upstream.in_flight;
    // The Instance may leave the table while the forward is in flight
    // (offline rows are swept after 2 × offline window; a re-register replaces
    // the row): callbacks look it up again by name, never through the pointer.
    const std::string module = inst.module, instance = inst.instance, address = inst.address;
    const std::string path = up.path;
    // Shared with the failure closure: a retry re-sends the same request, and
    // forward() serialises it synchronously, so one copy serves both attempts.
    auto up_ptr = std::make_shared<HttpRequest>(std::move(up));

    // The client's own id rides along (X-Client-Request-Id) so both journals
    // can be joined from either end.
    log_.debug("GatewayAPI: {} {} -> {}/{} {} (attempt {}, rid {}, client {})", up_ptr->method, path, module, instance,
               address, attempt, request_id, up_ptr->header("X-Client-Request-Id"));

    // Clamped at zero: a row swept (2 × offline window) and registered again
    // while this forward was in flight starts from in_flight = 0, and a
    // decrement below zero would make pick_instance prefer it for good.
    auto settle = [this, module, instance, address]() -> Instance* {
        if (auto u = upstreams_.find(address); u != upstreams_.end() && u->second.in_flight > 0)
            --u->second.in_flight;
        auto* i = find_instance(module, instance);
        if (i && i->in_flight > 0) --i->in_flight;
        return i;
    };

    upstream.proxy->forward(*up_ptr,
        [this, conn, ctx, request_id, settle](const HttpResponse& from_module) {
            if (auto* i = settle()) i->conn_errors = 0;   // a successful answer resets the passive counter
            HttpResponse r = from_module;
            shape_downstream(r, request_id);
            apply_refresh_cookies(r, ctx);
            conn->send_response(r);
        },
        [this, conn, ctx, request_id, settle, up_ptr, module, instance, address, path, attempt](const HttpProxy::ForwardFailure& f) {
            auto* i = settle();
            const std::string why(f.message);
            if (!f.request_sent) {
                // Connect refused / timed out: nothing reached the module. Passive check:
                // passive check — k_passive_errors in a row take it out of
                // rotation; one retry, on another ready instance.
                if (i && ++i->conn_errors >= k_passive_errors && i->state == "ready")
                    set_state(*i, "suspect", fmt::format("{} connect failures", i->conn_errors));
                log_.warn("GatewayAPI: {}/{} {}: connect failed ({}), attempt {} (rid {})", module, instance, address, why, attempt, request_id);
                if (attempt == 1) {
                    bool covered = false;
                    // Avoid by address, not by row: the row may be gone already
                    // (swept, or re-registered at the same dead address).
                    if (auto* other = pick_instance(path, address, covered)) {
                        forward_to(*other, std::move(*up_ptr), conn, ctx, request_id, 2);
                        return;
                    }
                }
                answer_problem(conn, ctx, 502, "upstream-error", "Bad Gateway",
                               fmt::format("no instance reachable: {}", why), path, request_id);
                return;
            }
            // Sent — the module may have executed it; never retried.
            log_.warn("GatewayAPI: {}/{} {}: no answer ({}) after send (rid {})", module, instance, address, why, request_id);
            using Reason = HttpProxy::ForwardFailure::Reason;
            if (f.reason == Reason::response_timeout || f.reason == Reason::idle_timeout)
                answer_problem(conn, ctx, 504, "upstream-timeout", "Gateway Timeout",
                               fmt::format("no complete answer within {} ms", response_timeout_ms_), path, request_id);
            else
                answer_problem(conn, ctx, 502, "upstream-error", "Bad Gateway",
                               fmt::format("upstream failed after the request was sent: {}", why), path, request_id);
        });
}

void GatewayAPI::answer_problem(const std::shared_ptr<HttpConnection>& conn, const ExecContext& ctx,
                                int status, std::string_view slug, std::string_view title,
                                std::string_view detail, std::string_view path,
                                std::string_view request_id, bool retry_after) const
{
    HttpResponse r;
    reply_problem(r, status, slug, title, detail, path, request_id);
    if (retry_after) r.set_header("Retry-After", "1");
    apply_refresh_cookies(r, ctx);   // a refresh that happened is not lost on a 5xx
    conn->send_response(r);
}

// ─── table ───────────────────────────────────────────────────────────────────

GatewayAPI::Instance* GatewayAPI::find_instance(const std::string& module, const std::string& instance)
{
    auto m = table_.find(module);
    if (m == table_.end()) return nullptr;
    auto i = m->second.find(instance);
    return i == m->second.end() ? nullptr : &i->second;
}

std::shared_ptr<GatewayAPI::Node> GatewayAPI::socket_of(const std::string& module, const std::string& instance) const
{
    for (const auto& [fd, node] : nodes_)
        if (node->registered && !node->closing && node->module == module && node->instance == instance)
            return node;
    return {};
}

void GatewayAPI::set_state(Instance& inst, std::string_view to, std::string_view reason)
{
    if (inst.state == to) return;
    log_.notice("GatewayAPI: {}/{} {} -> {} ({})", inst.module, inst.instance, inst.state, to, reason);
    inst.state = std::string(to);
    // The owner writes the transition; the trigger journals it and NOTIFYs
    // the other workers. A row this worker only mirrors changes in memory
    // alone (the passive suspect on a foreign instance): the owner's
    // view returns with the next NOTIFY or reload — resolved by the last
    // record in the database. Memory stays the truth for own sockets
    // when the database is not there.
    if (owns(inst)) mirror_state(inst, reason);
}

bool GatewayAPI::prefix_covers(std::string_view prefix, std::string_view path)
{
    // "/api/v2/clients" covers "/api/v2/clients" and "/api/v2/clients/…",
    // not "/api/v2/clients2" — same boundary rule as prefixes_overlap.
    if (path.size() < prefix.size() || path.substr(0, prefix.size()) != prefix) return false;
    return path.size() == prefix.size() || path[prefix.size()] == '/';
}

GatewayAPI::Instance* GatewayAPI::pick_instance(std::string_view path, std::string_view avoid_address, bool& covered)
{
    covered = false;
    std::size_t best_len = 0;
    std::vector<Instance*> candidates;

    for (auto& [mod, insts] : table_)
        for (auto& [name, inst] : insts)
            for (const auto& prefix : inst.prefixes) {
                if (!prefix_covers(prefix, path)) continue;
                covered = true;
                if (inst.state != "ready" || (!avoid_address.empty() && inst.address == avoid_address)) continue;
                // Prefixes of different modules never overlap (409 at /register),
                // so every candidate at best_len carries the same prefix.
                if (prefix.size() > best_len) { best_len = prefix.size(); candidates.clear(); }
                if (prefix.size() == best_len) candidates.push_back(&inst);
                // One instance is one candidate: its prefixes never nest (422 at
                // /register, prefixes_overlap), so at most one of them covers
                // any path — the first match is the only match.
                break;
            }

    if (candidates.empty()) return nullptr;

    int least = candidates.front()->in_flight;
    for (const auto* c : candidates) least = std::min(least, c->in_flight);
    std::vector<Instance*> tied;
    for (auto* c : candidates)
        if (c->in_flight == least) tied.push_back(c);
    return tied[rr_++ % tied.size()];
}

std::string GatewayAPI::shape_upstream(HttpRequest& up, std::string_view at) const
{
    auto lower = [](std::string_view v) {
        std::string out(v);
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
        return out;
    };

    std::string client_request_id, forwarded_for, authorization;
    std::vector<std::pair<std::string, std::string>> kept;
    kept.reserve(up.headers.size() + 6);
    for (auto& [k, v] : up.headers) {
        const auto lk = lower(k);
        // Hop-by-hop and everything HttpProxy::forward writes itself
        // (Host, Content-Length when missing, Connection: close). A forwarded
        // "Connection: keep-alive" next to its "Connection: close" would be two
        // headers with opposite meaning; a forwarded Transfer-Encoding would
        // describe a body the parser has already de-chunked.
        if (lk == "connection" || lk == "keep-alive" || lk == "transfer-encoding" ||
            lk == "upgrade" || lk == "te" || lk == "trailer" || lk == "proxy-authorization" ||
            lk == "proxy-connection" || lk == "host")
            continue;
        if (lk == "cookie") continue;                       // always off
        if (lk == "x-request-id") { client_request_id = v; continue; }
        if (lk == "x-client-request-id") continue;          // ours to set
        if (lk == "x-forwarded-for") { forwarded_for = v; continue; }   // the last header wins, its last element below
        if (lk == "x-forwarded-proto" || lk == "x-gateway-worker") continue;
        if (lk == "authorization") { authorization = v; continue; }
        kept.emplace_back(std::move(k), std::move(v));
    }

    if (!at.empty())
        kept.emplace_back("Authorization", fmt::format("Bearer {}", at));
    else if (!authorization.empty())
        kept.emplace_back("Authorization", std::move(authorization));   // Basic/Session/Secret as they are

    auto request_id = new_uuid();
    kept.emplace_back("X-Request-Id", request_id);
    if (!client_request_id.empty())
        kept.emplace_back("X-Client-Request-Id", std::move(client_request_id));
    // Exactly one X-Forwarded-For with exactly one address: a reverse proxy
    // in front (nginx with $proxy_add_x_forwarded_for) APPENDS its remote_addr
    // to whatever the client sent — so only the last element is the proxy's
    // word, everything before it is the client's. Keep the last element; the
    // module reads a single value. HttpProxy's own appending is off.
    if (auto comma = forwarded_for.rfind(','); comma != std::string::npos)
        forwarded_for.erase(0, comma + 1);
    while (!forwarded_for.empty() && (forwarded_for.front() == ' ' || forwarded_for.front() == '\t'))
        forwarded_for.erase(0, 1);
    while (!forwarded_for.empty() && (forwarded_for.back() == ' ' || forwarded_for.back() == '\t'))
        forwarded_for.pop_back();
    if (forwarded_for.empty()) {
        forwarded_for = up.peer_ip;
        // Dual-stack listener: an IPv4 peer is "::ffff:a.b.c.d" — as in add_node.
        if (forwarded_for.rfind("::ffff:", 0) == 0) forwarded_for.erase(0, 7);
    }
    kept.emplace_back("X-Forwarded-For", std::move(forwarded_for));
    kept.emplace_back("X-Forwarded-Proto", "https");
    kept.emplace_back("X-Gateway-Worker", std::to_string(pid_));

    up.headers = std::move(kept);
    return request_id;
}

void GatewayAPI::shape_downstream(HttpResponse& r, std::string_view request_id)
{
    // HttpResponse has no header enumeration and del_header is case-sensitive:
    // the canonical spelling is what most HTTP stacks (Go's net/http among
    // them) write. A case-insensitive sweep needs a headers() accessor in
    // libapostol; until then these two.
    r.del_header("Set-Cookie");
    r.del_header("set-cookie");
    r.set_header("X-Request-Id", std::string(request_id));
}

json GatewayAPI::table_json() const
{
    json out = json::array();
    const auto now = clock_t_::now();
    for (const auto& [mod, insts] : table_)
        for (const auto& [name, inst] : insts)
            out.push_back({
                {"module",       inst.module},
                {"instance",     inst.instance},
                {"version",      inst.version},
                {"build",        inst.build},
                {"address",      inst.address},
                {"prefixes",     inst.prefixes},
                {"capacity",     inst.capacity},
                {"state",        inst.state},
                {"in_flight",    inst.reported_in_flight},
                {"load",         inst.load},
                {"local_in_flight", inst.in_flight},
                {"conn_errors",  inst.conn_errors},
                {"registered_s", seconds_since(inst.registered, now)},
                {"seen_s",       seconds_since(inst.last_heartbeat, now)},
                {"owner_worker", inst.owner_worker},
                {"source",       inst.source == Source::socket ? "socket" : "mirror"},
            });
    return out;
}

void GatewayAPI::on_stop()
{
    // ModuleManager::on_stop() runs right after loop.run() returns, with the
    // loop object still alive (application.cpp, *_run). ~HttpProxy itself
    // does not touch the loop (weak tokens), but a forward still in flight
    // does: ~ForwardCtx → ~TcpClient cancels its connect/idle timers and
    // removes its fd. Left to ~GatewayAPI that would run from ~Application on
    // a loop that no longer exists (gdb: cancel_timer on a dead
    // unordered_map). In-flight forwards are dropped with their
    // contexts — the connections they would have answered are closing anyway;
    // the shutdown drain (drain_db) counts database queries only, so a
    // forward gets no grace the way an AppServer query does.
    upstreams_.clear();
}

// ─── clock ───────────────────────────────────────────────────────────────────

void GatewayAPI::heartbeat(clock_t_::time_point now)
{
    // Called once a second by the application's module timer; no throttle of
    // our own — a `now + 1s` gate skipped every other tick when the timer
    // fired a millisecond early, and the stub measured transitions a second late.

    // LISTEN once (PgPool::listen is not idempotent — it would stack a
    // second handler); the pool restores the subscription itself when its
    // listener connection is lost.
    if (!listen_armed_) {
        listen_armed_ = true;
        db_.listen("gateway", [this](std::string_view, std::string_view payload) { on_gateway_notify(payload); });
        next_seen_   = now + std::chrono::seconds(heartbeat_interval_);
        next_reload_ = now + std::chrono::seconds(1);   // first reload right away: a worker that just
                                                          // came up learns the fleet before its first request
    }
    if (now >= next_seen_)   { next_seen_   = now + std::chrono::seconds(heartbeat_interval_); mirror_seen(now); }
    if (now >= next_reload_) { next_reload_ = now + std::chrono::seconds(reload_interval_);    mirror_reload();  }
    if (mirror_busy_ && seconds_since(mirror_sent_, now) >= reload_interval_)
        mirror_warn("write", fmt::format("outstanding for {} s, {} more queued", seconds_since(mirror_sent_, now),
                                         mirror_queue_.size()));

    // Copy: close_node/drop_node mutate nodes_.
    std::vector<std::shared_ptr<Node>> nodes;
    nodes.reserve(nodes_.size());
    for (auto& [fd, node] : nodes_) nodes.push_back(node);

    for (auto& node : nodes) {
        if (node->closing) {
            if (now >= node->close_deadline)
                drop_node(node);   // peer never answered our close frame
            continue;
        }

        // /register within 5 s of the upgrade.
        if (!node->registered) {
            if (seconds_since(node->connected, now) >= k_register_deadline_s) {
                log_.warn("GatewayAPI: {}/{} from {}: no /register within {} s", node->module,
                          node->instance, node->peer_ip, k_register_deadline_s);
                close_node(node, 1008, "register timeout");
            }
            continue;
        }

        // Our CALLs answered within 5 s.
        for (auto it = node->pending.begin(); it != node->pending.end();) {
            if (seconds_since(it->second.sent, now) >= k_call_timeout_s) {
                log_.warn("GatewayAPI: {}/{}: {} not answered in {} s", node->module, node->instance,
                          it->second.action, k_call_timeout_s);
                if (it->second.http_conn) {
                    HttpResponse r;
                    reply_problem(r, 504, "upstream-timeout", "Gateway Timeout",
                                  fmt::format("{} not answered in {} s", it->second.action, k_call_timeout_s),
                                  control_path_);
                    std::static_pointer_cast<HttpConnection>(it->second.http_conn)->send_response(r);
                }
                it = node->pending.erase(it);
            } else {
                ++it;
            }
        }

        // suspect / offline by the clock, not by a counter (README § Instance states).
        auto* inst = find_instance(node->module, node->instance);
        if (!inst || inst->owner_worker != pid_ || inst->source != Source::socket) continue;
        const int silent = seconds_since(inst->last_heartbeat, now);
        if (silent >= offline_after_ * heartbeat_interval_) {
            set_state(*inst, "offline", fmt::format("no heartbeat for {} s", silent));
            close_node(node, 4000, "heartbeat timeout");
        } else if (silent >= suspect_after_ * heartbeat_interval_ &&
                   (inst->state == "ready" || inst->state == "overloaded")) {
            set_state(*inst, "suspect", fmt::format("no heartbeat for {} s", silent));
        }
    }

    // Offline rows with no socket behind them leave the table after one
    // offline window — long enough for GET /gateway/list to show the
    // transition, short enough not to accumulate. gateway.log keeps the
    // history; memory does not. Mirror rows go the same way: their
    // last_heartbeat is the last time the database spoke about them.
    for (auto m = table_.begin(); m != table_.end();) {
        for (auto i = m->second.begin(); i != m->second.end();) {
            const auto& inst = i->second;
            bool has_socket = false;
            for (auto& [fd, node] : nodes_)
                if (node->registered && !node->closing && node->module == inst.module && node->instance == inst.instance)
                    has_socket = true;
            if (inst.state == "offline" && !has_socket &&
                seconds_since(inst.last_heartbeat, now) >= 2 * offline_after_ * heartbeat_interval_) {
                log_.notice("GatewayAPI: {}/{} removed from the table (offline, no socket)", inst.module, inst.instance);
                i = m->second.erase(i);
            } else {
                ++i;
            }
        }
        if (m->second.empty()) m = table_.erase(m); else ++m;
    }

    // An HttpProxy per upstream address lives as long as some instance is
    // registered at it or a forward is still in flight through it. A pod
    // that came back under a new address leaves its old proxy here otherwise.
    for (auto u = upstreams_.begin(); u != upstreams_.end();) {
        bool in_table = false;
        for (const auto& [mod, insts] : table_)
            for (const auto& [name, inst] : insts)
                if (inst.address == u->first) in_table = true;
        if (!in_table && u->second.in_flight == 0) u = upstreams_.erase(u); else ++u;
    }
}

// ─── mirror in gateway.node (README § Mirror) ─────────────────────────────────────

std::string GatewayAPI::sql_ident(std::string_view module, std::string_view instance)
{
    return fmt::format("module = {} AND instance = {}", pq_quote_literal(module), pq_quote_literal(instance));
}

std::string GatewayAPI::sql_prefixes(const std::vector<std::string>& prefixes)
{
    std::string out = "ARRAY[";
    for (std::size_t i = 0; i < prefixes.size(); ++i) {
        if (i) out += ", ";
        out += pq_quote_literal(prefixes[i]);
    }
    out += "]::text[]";
    return out;
}

void GatewayAPI::mirror_warn(std::string_view what, std::string_view error)
{
    // With the database away the gateway works from memory; say so once
    // per reload interval, not once per heartbeat of every instance.
    const auto now = clock_t_::now();
    if (now < mirror_warned_) return;
    mirror_warned_ = now + std::chrono::seconds(reload_interval_);
    log_.warn("GatewayAPI: mirror: {} failed — routing from memory, the database will be re-read in {} s: {}",
              what, reload_interval_, error);
}

void GatewayAPI::mirror_exec(std::string sql, std::string what, PgQuery::ResultHandler on_result, std::string kind)
{
    if (!kind.empty())
        std::erase_if(mirror_queue_, [&](const MirrorWrite& w) { return w.kind == kind; });
    mirror_queue_.push_back({std::move(sql), std::move(what), std::move(on_result), std::move(kind)});
    if (!mirror_busy_) mirror_next();
}

void GatewayAPI::mirror_next()
{
    if (mirror_queue_.empty()) { mirror_busy_ = false; return; }
    mirror_busy_ = true;
    mirror_sent_ = clock_t_::now();
    auto w = std::move(mirror_queue_.front());
    mirror_queue_.pop_front();
    auto what = w.what;
    // The pool queues a query while no connection is ready and re-queues one
    // cut off by a connection error — on_exception is for an SQL error only.
    // With the database away this write simply waits; heartbeat() notices
    // the age of mirror_sent_ and says so.
    db_.execute(std::move(w.sql),
        [this, what, on_result = std::move(w.on_result)](std::vector<PgResult> results) {
            if (on_result) {
                try { on_result(std::move(results)); }
                catch (const std::exception& e) { mirror_warn(what, e.what()); }
            }
            mirror_next();
        },
        [this, what](std::string_view error) {
            mirror_warn(what, error);
            mirror_next();
        },
        true);   // quiet: seen and sweep are periodic, transitions are logged by set_state
}

void GatewayAPI::mirror_upsert(const Instance& inst, std::string_view pre_reason, std::string_view reason, bool reassert)
{
    std::string sql;
    if (!pre_reason.empty())
        sql += fmt::format(
            "SELECT set_config('gateway.reason', {}, true);\n"
            "UPDATE gateway.node SET state = 'offline', updated = now() WHERE {} AND state <> 'offline';\n",
            pq_quote_literal(pre_reason), sql_ident(inst.module, inst.instance));
    sql += fmt::format(
        "SELECT set_config('gateway.reason', {}, true);\n"
        "INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker, registered, seen, updated)\n"
        "VALUES ({}, {}, {}, {}, {}, {}, {}, {}, now(), now(), now())\n"
        "ON CONFLICT (module, instance) DO UPDATE SET version = EXCLUDED.version, address = EXCLUDED.address,\n"
        "  prefixes = EXCLUDED.prefixes, state = EXCLUDED.state, capacity = EXCLUDED.capacity, worker = EXCLUDED.worker,\n"
        "  registered = {}, seen = now(), updated = now(){};",
        pq_quote_literal(reason),
        pq_quote_literal(inst.module), pq_quote_literal(inst.instance), pq_quote_literal(inst.version),
        pq_quote_literal(inst.address), sql_prefixes(inst.prefixes), pq_quote_literal(inst.state),
        inst.capacity, pid_,
        reassert ? "gateway.node.registered" : "now()",
        // A re-assert answers a snapshot; a register is the event itself and
        // overrides whatever the row says.
        reassert ? fmt::format("\n  WHERE gateway.node.worker = {} OR gateway.node.state = 'offline'", pid_) : "");
    // One simple-protocol query string: the statements run as ONE transaction
    // (no explicit BEGIN), so the transaction-local GUC reaches the trigger
    // and both NOTIFYs leave on the same commit, in this order.
    mirror_exec(std::move(sql), fmt::format("upsert {}/{}", inst.module, inst.instance));
}

void GatewayAPI::mirror_state(const Instance& inst, std::string_view reason)
{
    mirror_exec(fmt::format(
        "SELECT set_config('gateway.reason', {}, true);\n"
        "UPDATE gateway.node SET state = {}, updated = now() WHERE {} AND worker = {};",
        pq_quote_literal(reason), pq_quote_literal(inst.state), sql_ident(inst.module, inst.instance), pid_),
        fmt::format("state {}/{} -> {}", inst.module, inst.instance, inst.state));
    // `AND worker = pid`: the FIFO orders this worker's writes against each
    // other, not against another worker's. A transition queued here before
    // the NOTIFY of a takeover arrives, landing after the taker's upsert,
    // would otherwise re-claim the row — and the taker, reading a foreign
    // pid on its own live instance, would close its fresh socket. Every
    // caller either owns the row or has just read worker == pid from it.
}

void GatewayAPI::mirror_seen(clock_t_::time_point now)
{
    // `seen` moves once per interval and only for instances that actually
    // heartbeated in it — the sweep of the other workers reads it as "the
    // owner still hears this instance". now() of the database on both sides,
    // so the two clocks never meet.
    std::string rows;
    for (const auto& [mod, insts] : table_)
        for (const auto& [name, inst] : insts) {
            if (!owns(inst) || inst.state == "offline") continue;
            if (seconds_since(inst.last_heartbeat, now) > heartbeat_interval_) continue;
            if (!rows.empty()) rows += ", ";
            rows += fmt::format("({}, {})", pq_quote_literal(inst.module), pq_quote_literal(inst.instance));
        }
    if (rows.empty()) return;
    mirror_exec(fmt::format("UPDATE gateway.node SET seen = now() WHERE worker = {} AND (module, instance) IN ({});",
                            pid_, rows),
                "seen", {}, "seen");
}

void GatewayAPI::mirror_reload()
{
    // Sweep first, then read, in one transaction: rows of OTHER workers whose
    // `seen` is older than (offline_after + 1) intervals go offline — one
    // interval more than the owner's own clock, so a live owner always beats
    // the sweep and it only ever finishes what a dead worker left behind.
    // By `seen`, not by pid: a gateway replica in another container sees no
    // pid of ours, and kill -0 there would read every live row as dead.
    // Own rows are excluded — a stale `seen` of this pid is a row of a
    // previous life of this pid, or a database that was away: both are
    // settled below, by socket, not by age. The read carries the whole row
    // as JSON so text[] never has to be parsed here.
    const int stale_s = (offline_after_ + 1) * heartbeat_interval_;
    std::string sql = fmt::format(
        "SELECT set_config('gateway.reason', {}, true);\n"
        "UPDATE gateway.node SET state = 'offline', updated = now()\n"
        " WHERE state <> 'offline' AND worker IS DISTINCT FROM {} AND seen < now() - make_interval(secs => {});\n"
        "SELECT coalesce(json_agg(n), '[]'::json)::text FROM (\n"
        "  SELECT module, instance, version, address, prefixes, state, capacity, worker,\n"
        "         extract(epoch FROM now() - seen)::int AS seen_s, extract(epoch FROM now() - registered)::int AS registered_s\n"
        "    FROM gateway.node WHERE state <> 'offline') n;",
        pq_quote_literal(fmt::format("swept by worker {}: seen older than {} s", pid_, stale_s)), pid_, stale_s);

    mirror_exec(std::move(sql), "sweep+reload", [this](std::vector<PgResult> results) {
        if (results.empty() || results.back().rows() != 1) { mirror_warn("reload", "no result row"); return; }
        json rows;
        try { rows = json::parse(results.back().value(0, 0)); }
        catch (const std::exception& e) { mirror_warn("reload", e.what()); return; }
        if (!rows.is_array()) { mirror_warn("reload", "not an array"); return; }

        const auto now = clock_t_::now();
        std::map<std::string, std::map<std::string, bool>> seen;   // (module, instance) present in the database
        for (const auto& row : rows) {
            if (!row.is_object() || !row.contains("module") || !row.contains("instance")) continue;
            const std::string module = row["module"].get<std::string>();
            const std::string instance = row["instance"].get<std::string>();
            const int worker = int_or(row, "worker", 0);
            seen[module][instance] = true;

            auto* mine = find_instance(module, instance);
            if (mine && owns(*mine) && socket_of(module, instance)) {
                // The snapshot may predate our own /register queued behind
                // the reload: the row's `registered` is then older than ours
                // and its worker is stale. The upsert in the queue settles it.
                if (row.contains("registered_s") && row["registered_s"].is_number() &&
                    now - std::chrono::seconds(row["registered_s"].get<int>()) < mine->registered - std::chrono::seconds(1))
                    continue;
                if (worker != pid_) {
                    // A NOTIFY we missed: another worker holds the instance now.
                    take_over(module, instance, worker);
                    mirror_apply(row, "reload");
                } else if (row.value("state", "") != mine->state) {
                    // Someone (the sweep, a database that was away) has the
                    // row wrong: the socket is the truth, re-assert it.
                    mirror_upsert(*mine, {}, "owner re-asserted", true);
                }
                continue;
            }
            if (worker == pid_) {
                // The row claims this pid and there is no socket behind it:
                // a previous life of this pid, or a socket closed while the
                // database was away. Close it in the database.
                Instance gone;
                gone.module = module; gone.instance = instance; gone.state = "offline";
                mirror_state(gone, "no socket on worker");
                if (mine) { mine->state = "offline"; mine->last_heartbeat = now; }
                continue;
            }
            mirror_apply(row, "reload");
        }

        for (auto& [mod, insts] : table_)
            for (auto& [name, inst] : insts) {
                const bool present = seen.count(mod) && seen[mod].count(name);
                if (present || inst.state == "offline") continue;
                if (owns(inst) && socket_of(mod, name)) {
                    // Missing or offline in the database while the socket is
                    // alive — the database was away when we wrote, or the sweep
                    // beat a `seen` that never arrived. Ours: re-assert.
                    mirror_upsert(inst, {}, "owner re-asserted", true);
                } else if (inst.source == Source::mirror) {
                    log_.notice("GatewayAPI: {}/{} {} -> offline (mirror: not in gateway.node)", mod, name, inst.state);
                    inst.state = "offline";
                    inst.last_heartbeat = now;
                }
            }
    }, "reload");
}

void GatewayAPI::mirror_apply(const json& row, std::string_view why)
{
    // A row of ANOTHER worker: whatever the database says is what this worker
    // routes by. Fields not in the NOTIFY payload (version, capacity) arrive
    // with the reload; the routing ones — address, prefixes, state — are in both.
    const std::string module   = row.value("module", "");
    const std::string instance = row.value("instance", "");
    const std::string state    = row.value("state", "");
    if (module.empty() || instance.empty() || state.empty()) return;

    const auto now = clock_t_::now();
    auto* known = find_instance(module, instance);
    if (!known && state == "offline") return;   // nothing to route to, nothing to forget
    Instance& inst = known ? *known : table_[module][instance];
    const bool fresh = !known;
    const std::string from = fresh ? "(none)" : inst.state;
    inst.module   = module;
    inst.instance = instance;
    if (row.contains("version") && row["version"].is_string())    inst.version  = row["version"].get<std::string>();
    if (row.contains("capacity") && row["capacity"].is_number())  inst.capacity = row["capacity"].get<int>();
    if (row.contains("address") && row["address"].is_string()) {
        inst.address = row["address"].get<std::string>();
        std::string host; uint16_t port = 0;
        if (parse_address(inst.address, host, port)) { inst.host = host; inst.port = port; }
    }
    if (row.contains("prefixes") && row["prefixes"].is_array()) {
        inst.prefixes.clear();
        for (const auto& p : row["prefixes"]) if (p.is_string()) inst.prefixes.push_back(p.get<std::string>());
    }
    inst.owner_worker = int_or(row, "worker", 0);
    inst.source       = Source::mirror;
    inst.conn_errors  = 0;   // the owner hears it; our passive count starts over
    inst.last_heartbeat = row.contains("seen_s") && row["seen_s"].is_number()
                            ? now - std::chrono::seconds(row["seen_s"].get<int>()) : now;
    if (fresh)
        inst.registered = row.contains("registered_s") && row["registered_s"].is_number()
                            ? now - std::chrono::seconds(row["registered_s"].get<int>()) : now;
    if (fresh || inst.state != state) {
        log_.notice("GatewayAPI: {}/{} {} -> {} (mirror: {}, worker {})", module, instance, from, state, why, inst.owner_worker);
        inst.state = state;
    }
}

void GatewayAPI::take_over(const std::string& module, const std::string& instance, int by_worker)
{
    // The database says another worker holds this instance now — the module
    // reconnected there (its old socket to us may still be open, or the
    // NOTIFY of our own offline is still in flight). The earlier socket is
    // the replaced one. registered=false so drop_node leaves the row, now
    // theirs, alone.
    if (auto node = socket_of(module, instance)) {
        log_.notice("GatewayAPI: {}/{}: replaced by worker {} — closing our socket fd={}", module, instance,
                    by_worker, node->ws->fd());
        node->registered = false;
        close_node(node, 1001, "replaced");
    }
}

void GatewayAPI::on_gateway_notify(std::string_view payload)
{
    // Anything on the channel reaches here — a NOTIFY from psql included —
    // and nothing above catches: a throw would end the worker.
    try { on_gateway_notify_(payload); }
    catch (const std::exception& e) { log_.warn("GatewayAPI: NOTIFY gateway ignored ({}): {}", e.what(), payload); }
}

void GatewayAPI::on_gateway_notify_(std::string_view payload)
{
    json msg = json::parse(payload);
    if (!msg.is_object()) return;

    const std::string module   = msg.value("module", "");
    const std::string instance = msg.value("instance", "");
    const std::string op       = msg.value("op", "");
    const int         worker   = int_or(msg, "worker", 0);
    if (module.empty() || instance.empty()) return;
    if (op == "DELETE") msg["state"] = "offline";

    auto* mine = find_instance(module, instance);
    if (mine && owns(*mine) && worker == pid_ && !socket_of(module, instance)) {
        // The echo of our own offline for a socket already gone: memory has
        // it; mirroring it back would re-stamp the row source=mirror.
        if (msg.value("state", "") == "offline") mine->state = "offline";
        return;
    }
    if (mine && owns(*mine) && socket_of(module, instance)) {
        // Our row. `worker` in the payload is the row's column, not the writer:
        // our own writes come back with our pid, and so does a sweep of our row
        // by another worker. Neither is acted on here — the socket is the
        // truth, and the reload re-asserts a row the database has wrong. Acting
        // on the offline would fight the register of a worker taking the
        // instance over (its offline step keeps our pid) — the ready that
        // follows, with ITS pid, is the takeover.
        if (worker != pid_ && msg.value("state", "") != "offline") {
            take_over(module, instance, worker);
            mirror_apply(msg, "notify");
        }
        return;
    }
    mirror_apply(msg, "notify");
}

} // namespace apostol
