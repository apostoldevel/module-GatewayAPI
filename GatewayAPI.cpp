// GatewayAPI — control plane and routing table. See GatewayAPI.hpp.

#include "GatewayAPI.hpp"

#include "apostol/application.hpp"
#include "apostol/base64.hpp"
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
#include <cctype>
#include <limits>
#include <random>
#include <tuple>

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

// The refusal of `prefixes` of `module` by the prefixes held by the OTHER
// modules of `claims` (module → prefixes), the /register 409 text; empty —
// none overlaps.
std::string held_by(const std::map<std::string, std::vector<std::string>>& claims, const std::string& module,
                    const std::vector<std::string>& prefixes)
{
    for (const auto& [mod, theirs] : claims) {
        if (mod == module) continue;
        for (const auto& t : theirs)
            for (const auto& mine : prefixes)
                if (prefixes_overlap(t, mine))
                    return fmt::format("prefix {} belongs to module {}", mine, mod);
    }
    return {};
}

// json::value() throws on a key whose value is null; gateway.node.worker is
// nullable and a row written by another application may leave it so.
int int_or(const nlohmann::json& o, const char* key, int def)
{
    auto it = o.find(key);
    return it != o.end() && it->is_number_integer() ? it->get<int>() : def;
}

// The same for a string. A frame's fields are read through these two, not
// json::value(): value() throws on a field of another type, and a frame is
// handled in the socket's epoll callback, where an exception that escapes
// ends the worker.
std::string str_or(const nlohmann::json& o, const char* key, std::string def)
{
    auto it = o.find(key);
    return it != o.end() && it->is_string() ? it->get<std::string>() : std::move(def);
}

// Deepest nesting accepted in JSON from a module or a control-plane caller.
// nlohmann parses without recursion but copies and serialises recursively:
// a frame nested deep enough overflows the worker's stack even under the
// 64 KiB frame limit (measured: ~11k levels on a debug build). That is a
// signal, not an exception — no catch sees it. The protocol nests a few
// levels; 128 is far above them.
constexpr int k_max_json_depth = 128;

json parse_bounded(const std::string& text)
{
    return json::parse(text, [](int depth, json::parse_event_t, json&) {
        if (depth > k_max_json_depth)
            throw std::out_of_range("JSON nested deeper than allowed");
        return true;
    });
}

// gateway.node.node is nullable: NULL (a binary that does not write it), or
// absent from an older trigger's payload — both read as "".
std::string node_of(const nlohmann::json& o)
{
    auto it = o.find("node");
    return it != o.end() && it->is_string() ? it->get<std::string>() : std::string{};
}

} // namespace

// ─── ctor / config ───────────────────────────────────────────────────────────

GatewayAPI::GatewayAPI(Application& app)
    : AppServer(app)
    , loop_(app.worker_loop())
    , db_(app.db_pool())
    , node_(app.node_id())
    , pid_(static_cast<int>(::getpid()))
    , self_(app.node_process_id())
{
    add_allowed_header("Authorization");

    // The identity goes into a request header (X-Gateway-Worker), the log and
    // JSON answers: a NODE_NAME with a control byte, a space or a non-ASCII
    // byte would split a header or make a dump() throw. Anything outside
    // printable ASCII becomes '_' — for this module only.
    if (node_.empty() || !std::all_of(node_.begin(), node_.end(), [](unsigned char c) { return c > 0x20 && c < 0x7F; })) {
        std::string clean = node_.empty() ? std::string("_") : node_;
        for (auto& c : clean)
            if (static_cast<unsigned char>(c) <= 0x20 || static_cast<unsigned char>(c) >= 0x7F) c = '_';
        log_.warn("GatewayAPI: node identity has bytes outside printable ASCII (or is empty) — used as '{}'", clean);
        node_ = std::move(clean);
        self_ = fmt::format("{}:{}", node_, pid_);
    }

    if (const auto* cfg = app.module_config("GatewayAPI")) {
        control_path_        = cfg->value("control_path", control_path_);
        connect_timeout_ms_  = cfg->value("connect_timeout_ms", connect_timeout_ms_);
        response_timeout_ms_ = cfg->value("response_timeout_ms", response_timeout_ms_);
        reload_interval_     = cfg->value("reload_interval", reload_interval_);
        heartbeat_interval_ = cfg->value("heartbeat_interval", heartbeat_interval_);
        suspect_after_      = cfg->value("suspect_after", suspect_after_);
        offline_after_      = cfg->value("offline_after", offline_after_);
        audience_           = cfg->value("audience", audience_);

        // Exact paths under /api/v2 that run as their API v1 twin
        // (README § API v1 routes). Empty by default: then nothing changes.
        if (cfg->contains("v1_routes")) {
            const auto& routes = (*cfg)["v1_routes"];
            if (routes.is_array()) {
                for (const auto& item : routes) {
                    if (!item.is_string() || !valid_prefix(item.get<std::string>())) {
                        log_.warn("GatewayAPI: v1_routes entry {} ignored (^/api/v2/[a-z0-9_/-]+$, no trailing '/')",
                                  item.dump());
                        continue;
                    }
                    auto path = item.get<std::string>();
                    if (std::find(v1_routes_.begin(), v1_routes_.end(), path) == v1_routes_.end())
                        v1_routes_.push_back(std::move(path));
                }
            } else {
                log_.warn("GatewayAPI: v1_routes ignored (an array of paths, got {})", routes.type_name());
            }
        }

        // An array, or one string "a.b.c.d/n, e.f.g.h/m" — the form a value
        // taken from the environment ("${GATEWAY_ALLOWED_CIDR}") arrives in:
        // substitution happens inside strings only. A blank string is an
        // absent key: the default [] refuses every registration.
        std::vector<std::string> entries;
        if (cfg->contains("allowed_cidr")) {
            const auto& node = (*cfg)["allowed_cidr"];
            if (node.is_array()) {
                for (const auto& item : node) {
                    if (item.is_string()) entries.push_back(item.get<std::string>());
                    else log_.warn("GatewayAPI: allowed_cidr entry {} ignored (not a string)", item.dump());
                }
            } else if (node.is_string()) {
                const std::string list = node.get<std::string>();
                std::size_t from = 0;
                while (from <= list.size()) {
                    std::size_t comma = list.find(',', from);
                    if (comma == std::string::npos) comma = list.size();
                    std::string_view item = std::string_view(list).substr(from, comma - from);
                    while (!item.empty() && std::isspace(static_cast<unsigned char>(item.front()))) item.remove_prefix(1);
                    while (!item.empty() && std::isspace(static_cast<unsigned char>(item.back()))) item.remove_suffix(1);
                    if (!item.empty()) entries.emplace_back(item);
                    from = comma + 1;
                }
            } else {
                log_.warn("GatewayAPI: allowed_cidr ignored (an array or a comma-separated string, got {})", node.type_name());
            }
        }
        for (const auto& s : entries) {
            auto slash = s.find('/');
            std::string ip   = s.substr(0, slash);
            // No std::stoi: a typo like "10.0.0.0/" or "/xx" would throw
            // out of the constructor and take the worker down at start.
            int bits = 32;
            if (slash != std::string::npos) {
                bits = 0;
                std::string_view digits = std::string_view(s).substr(slash + 1);
                // "/00" would read as /0 and open every address: a typo must
                // not widen the list, so a two-digit length never starts with 0.
                if (digits.empty() || digits.size() > 2 || (digits.size() == 2 && digits[0] == '0')) bits = -1;
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

    log_.notice("GatewayAPI: {} control_path={} heartbeat_interval={}s suspect_after={} offline_after={} audience={} cidr={} v1_routes={}",
                self_, control_path_, heartbeat_interval_, suspect_after_, offline_after_, audience_,
                allowed_cidr_.size(), v1_routes_.size());
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

// The aud claim of a token whose signature verify_jwt has already checked —
// read from the payload, which verify_jwt does not hand back on expiry.
static std::string token_audience(std::string_view token)
{
    const auto first = token.find('.');
    const auto second = first == std::string_view::npos ? first : token.find('.', first + 1);
    if (second == std::string_view::npos)
        return {};

    std::string b64(token.substr(first + 1, second - first - 1));
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    while (b64.size() % 4)
        b64 += '=';

    try {
        const auto payload = json::parse(base64_decode(b64));
        const auto it = payload.find("aud");
        if (it != payload.end() && it->is_string())
            return it->get<std::string>();
    } catch (const std::exception&) {
    }
    return {};
}

std::string GatewayAPI::check_gateway_token(const HttpRequest& req) const
{
    // Nothing to check is its own answer: RFC 6750 §3.1 wants a bare challenge
    // for a request that carried no credentials, not invalid_token.
    auto auth = parse_authorization(req.header("Authorization"));
    if (auth.schema != Authorization::Schema::bearer || auth.token.empty())
        return "no-credentials";
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
        // Expired — but whose? verify_jwt checks the signature before the
        // expiry (measured: an expired token with a wrong signature is
        // "invalid"), so the aud read here is authentic. A token of another
        // audience gets the answer a valid one of another audience gets:
        // saying "expired" to it tells the caller it holds a genuinely signed
        // token, which the control plane has no business confirming.
        const auto* app = providers_.find_default(audience_);
        if (!app || token_audience(auth.token) != app->client_id)
            return "unauthorized";
        return "expired";
    } catch (const std::exception&) {
        // JwtVerificationError — and anything else verify_jwt lets out on a
        // string that is not a token at all (base64 "too much fill" from a
        // garbage Bearer, measured with the stub). Same answer either way.
        return "unauthorized";
    }
}

void GatewayAPI::reply_problem(HttpResponse& resp, int status, std::string_view slug,
                               std::string_view title, std::string_view detail,
                               std::string_view instance_path, std::string_view request_id,
                               bool no_credentials) const
{
    const std::string rid = request_id.empty() ? new_uuid() : std::string(request_id);

    // Every 401 the gateway answers itself — the data plane's refusals of
    // check_auth and the control plane's of check_gateway_token alike — is
    // decided here, so no new call site can forget either half:
    //
    //   - RFC 6750 §3: a bearer resource's 401 carries the challenge. The host
    //     behind the gateway sets its own; these are answered before a request
    //     ever reaches it.
    //   - The catalogue id the go-platform host gives the same case, so one case
    //     reads one code whichever producer refused it.
    //     Every way a token fails to verify is one code: ERR-401-007 "signature
    //     is incorrect" would tell a prober which check it passed.
    //
    // A request with no credentials at all gets the bare challenge (§3.1) and
    // the host's code for the same case, ERR-401-001.
    //
    // Other statuses keep code null: the gateway has no catalogue id for them.
    std::string_view code;
    if (status == 401) {
        set_challenge(resp, detail, no_credentials);
        code = slug == "token-expired" ? "ERR-401-008" : "ERR-401-001";
    }

    json body = {
        {"type",       fmt::format("urn:apostol:gateway:{}", slug)},
        {"title",      title},
        {"status",     status},
        {"detail",     detail},
        {"instance",   instance_path},
        {"request_id", rid},
        {"code",       code.empty() ? json(nullptr) : json(code)},
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
        // 401 for an expired token too (RFC 6750 §3.1: invalid_token covers
        // "expired"); it was 403. The gateway client answers every 4xx of the
        // handshake the same way — a slow retry with a fresh token.
        reply_problem(resp, 401,
                      why == "expired" ? "token-expired" : "token-invalid",
                      "Unauthorized",
                      why == "expired" ? "gateway audience token expired"
                                       : "gateway audience token required",
                      req.path, {},
                      /*no_credentials=*/why == "no-credentials");
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
            if (covered || !table_loaded_) {
                reply_problem(resp, 503, miss_slug(covered), "Service Unavailable", miss_detail(covered), path);
                resp.set_header("Retry-After", "1");
            } else {
                reply_problem(resp, 404, "no-route", "Not Found", "no prefix covers the path", path);
            }
            return;
        }
        json out = {
            {"gateway_node",   self_},
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
        {"gateway_node",   self_},
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
        // 401 for an expired token too (RFC 6750 §3.1: invalid_token covers
        // "expired"); it was 403. The gateway client answers every 4xx of the
        // handshake the same way — a slow retry with a fresh token.
        reply_problem(resp, 401,
                      why == "expired" ? "token-expired" : "token-invalid",
                      "Unauthorized",
                      why == "expired" ? "gateway audience token expired"
                                       : "gateway audience token required",
                      req.path, {},
                      /*no_credentials=*/why == "no-credentials");
        return;
    }

    json p = json::object();
    if (!req.body.empty()) {
        try { p = parse_bounded(req.body); }
        catch (const std::exception&) { p = nullptr; }
        if (!p.is_object()) {
            reply_problem(resp, 400, "bad-request", "Bad Request", "body must be a JSON object", req.path);
            return;
        }
    }

    // Only the worker holding the socket can talk to the module.
    if (auto target = socket_of(module, instance)) {
        resp.set_deferred(true);
        send_call(target, "/" + command, p,
                  [this, conn = req.connection_ctx](const Answer& a) { respond(conn, a); });
        return;
    }

    // Held elsewhere — by the table: an instance it does not know, or knows
    // offline, is not relayed; before the first reload the table knows only
    // this worker's sockets, and a miss is not an answer yet.
    const auto* known = find_instance(module, instance);
    if (!known || known->state == "offline") {
        if (!table_loaded_) {
            reply_problem(resp, 503, miss_slug(false), "Service Unavailable", miss_detail(false), req.path);
            resp.set_header("Retry-After", "1");
        } else {
            reply_problem(resp, 404, "unknown-instance", "Not Found",
                          fmt::format("instance {}/{} is {}", module, instance, known ? "offline" : "not registered"),
                          req.path);
        }
        return;
    }
    if (!cmd_listening_) {
        // The holder's answer comes back over LISTEN gateway_cmd — not
        // confirmed yet on this worker (a fresh one, or the database away).
        reply_problem(resp, 503, "database-unavailable", "Service Unavailable",
                      "the command channel is not listening yet", req.path);
        resp.set_header("Retry-After", "1");
        return;
    }
    resp.set_deferred(true);
    relay_command(module, instance, command, p, req.connection_ctx);
}

void GatewayAPI::respond(const std::shared_ptr<void>& http_conn, const Answer& a) const
{
    if (!http_conn) return;
    HttpResponse r;
    if (a.status == 200)
        r.set_status(200, "OK").set_body(a.body.dump(), "application/json");
    else
        reply_problem(r, a.status, a.slug, a.title, a.detail, control_path_);
    if (a.status == 503) r.set_header("Retry-After", "1");
    std::static_pointer_cast<HttpConnection>(http_conn)->send_response(r);
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
    return check_gateway_token(req);   // "" | "no-credentials" | "unauthorized" | "expired"
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
    else if (refuse == "expired")
        reply_problem(resp, 401, "token-expired", "Unauthorized", "gateway audience token expired", req.path);
    else
        reply_problem(resp, 401, "token-invalid", "Unauthorized", "gateway audience token required", req.path, {},
                      /*no_credentials=*/refuse == "no-credentials");
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
    // A control frame carries at most 125 bytes (RFC 6455 §5.5): two of the
    // code, 123 of the reason. A longer one — a long prefix in "prefix …
    // belongs to module …" — would be a protocol error, not the refusal.
    // The reasons are ASCII (names and prefixes by their patterns).
    node->ws->send_close(code, reason.substr(0, 123));
    // Any HTTP caller waiting on this node gets 502 now.
    auto pending = std::move(node->pending);
    node->pending.clear();
    for (auto& [u, call] : pending)
        if (call.answer)
            call.answer({502, {}, "upstream-error", "Bad Gateway",
                         fmt::format("socket closed ({}) before {} was answered", reason, call.action)});
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

    auto pending = std::move(node->pending);
    node->pending.clear();
    for (auto& [u, call] : pending)
        if (call.answer)
            call.answer({502, {}, "upstream-error", "Bad Gateway",
                         fmt::format("socket closed before {} was answered", call.action)});

    // A close WE started (unregister, heartbeat timeout, replacement) wrote
    // the state before calling close_node; only a close the PEER started
    // (EOF, reset, protocol error) is recorded here. A replaced node has
    // registered=false, so it never touches the row now owned by its successor.
    if (node->registered && !node->closing)
        if (auto* inst = find_instance(node->module, node->instance); inst && owns(*inst))
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
                           const json& p, AnswerFn answer)
{
    const std::string u = new_uuid();
    node->pending[u] = PendingCall{std::string(action), clock_t_::now(), std::move(answer)};
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

    // This runs in the socket's epoll callback, outside the HTTP dispatcher's
    // try: an exception that leaves it ends the worker process, every node
    // and every HTTP call in flight on it. Fields are read by type
    // (int_or/str_or), and whatever still throws below is answered, not
    // propagated. A catch does not cover a stack overflow: the depth is
    // bounded at parse, and p is moved out, not copied.
    json msg;
    try { msg = parse_bounded(payload); }
    catch (const std::out_of_range&) {
        log_.warn("GatewayAPI: {}/{} from {}: frame nested deeper than {} refused", node->module,
                  node->instance, node->peer_ip, k_max_json_depth);
        send_call_error(*node->ws, "", 400, fmt::format("frame nested deeper than {}", k_max_json_depth));
        return;
    }
    catch (const std::exception&) { msg = nullptr; }
    if (!msg.is_object()) {
        send_call_error(*node->ws, "", 400, "frame is not a JSON object");
        return;
    }
    const int t = int_or(msg, "t", -1);
    const std::string u = str_or(msg, "u", "");

    try {
        switch (t) {
            case 2: {
                if (u.empty()) { send_call_error(*node->ws, "", 400, "missing u"); return; }
                // "duplicate u in flight" cannot happen here: every CALL is
                // answered synchronously inside this callback, so nothing from
                // the module is ever in flight when the next frame is parsed.
                auto a = msg.find("a");
                if (a == msg.end() || !a->is_string()) {
                    send_call_error(*node->ws, u, 400, "missing or non-string a");
                    return;
                }
                const std::string action = a->get<std::string>();
                json p = json::object();
                if (auto it = msg.find("p"); it != msg.end()) p = std::move(*it);
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
    } catch (const json::exception& e) {
        log_.warn("GatewayAPI: {}/{} from {}: frame refused: {}", node->module, node->instance,
                  node->peer_ip, e.what());
        if (!node->closing) send_call_error(*node->ws, u, 400, "invalid message");
    } catch (const std::exception& e) {
        log_.error("GatewayAPI: {}/{} from {}: frame failed: {}", node->module, node->instance,
                   node->peer_ip, e.what());
        if (!node->closing) send_call_error(*node->ws, u, 500, "internal error");
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
    const std::string u = str_or(msg, "u", "");
    auto it = node->pending.find(u);
    if (it == node->pending.end()) {
        log_.debug("GatewayAPI: {}/{}: reply to unknown u={}", node->module, node->instance, u);
        return;
    }
    PendingCall call = std::move(it->second);
    node->pending.erase(it);

    const int t = int_or(msg, "t", -1);
    log_.debug("GatewayAPI: {}/{}: {} answered ({}) in {} ms", node->module, node->instance,
               call.action, t == 3 ? "result" : "error",
               std::chrono::duration_cast<std::chrono::milliseconds>(clock_t_::now() - call.sent).count());

    if (!call.answer) return;
    // The call is already out of pending: whatever happens below, the caller
    // is answered here or never — nothing else will find it. Fields
    // are read by type: c/m of another type must not throw past the answer.
    Answer a;
    if (t == 3) {
        auto p = msg.find("p");
        a = {200, p != msg.end() ? *p : json::object(), {}, {}, {}};
    } else {
        a = {502, {}, "upstream-error", "Bad Gateway",
             fmt::format("module answered {} with {}: {}", call.action,
                         int_or(msg, "c", 0), str_or(msg, "m", ""))};
    }
    try {
        call.answer(a);
    } catch (const std::exception& e) {
        log_.warn("GatewayAPI: {}/{}: reply to {} refused: {}", node->module, node->instance,
                  call.action, e.what());
        call.answer({502, {}, "upstream-error", "Bad Gateway",
                     fmt::format("module answered {} with a malformed reply", call.action)});
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

    // 422 — a row whose NOTIFY would not fit: pg_notify refuses a payload of
    // 8000 bytes or more, the upsert fails with it, and the instance never
    // reaches the other workers. The trigger's json_build_object writes
    // "key" : value, ... — two bytes per key and one per element more than a
    // compact dump — and `updated` as a timestamp of up to 35 characters.
    {
        const json probe = {{"op", "UPDATE"}, {"module", node->module}, {"instance", node->instance},
                            {"state", "overloaded"}, {"state_from", "overloaded"}, {"address", p["address"]},
                            {"prefixes", prefixes}, {"worker", pid_}, {"node", node_},
                            {"updated", std::string(35, '0')}};
        const std::size_t bytes = probe.dump().size() + 3 * probe.size() + prefixes.size();
        if (bytes > k_notify_max_bytes) {
            fail(422, fmt::format("registration too large for the mirror NOTIFY ({} bytes, the channel carries {})",
                                  bytes, k_notify_max_bytes));
            return;
        }
    }
    if (host != node->peer_ip)
        log_.warn("GatewayAPI: {}/{}: address {} differs from socket peer {} (allowed)",
                  node->module, node->instance, host, node->peer_ip);

    // Until the first reload this worker knows only its own sockets: a prefix
    // of another module registered on another worker would pass the check
    // below and stay here for good. Not a refusal of the module —
    // no CALLERROR; close 1013 sends it to the common back-off, and
    // the table is loaded by the time it comes back (about a second).
    // A database still away after k_register_wait_s: the registration is
    // taken as before — the first reload settles a prefix held elsewhere —
    // so the worker routes its own sockets while it cannot read the table.
    if (!table_loaded_ && seconds_since(born_, clock_t_::now()) < k_register_wait_s) {
        log_.notice("GatewayAPI: {}/{} from {}: /register before the routing table is loaded — close 1013",
                    node->module, node->instance, node->peer_ip);
        close_node(node, 1013, "routing table loading");
        return;
    }

    // 409 — a prefix the gateway serves itself as an API v1 route
    if (const auto claim = v1_route_claim(prefixes); !claim.empty()) { fail(409, claim); return; }

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
    inst.owner_node   = node_;
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
        {"gateway_node",       self_},
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
    if (!p.contains("state") || !p["state"].is_string()) {
        send_call_error(*node->ws, u, 400, "missing or non-string state");
        return;
    }
    const std::string state = p["state"].get<std::string>();
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
    const std::string reason = str_or(p, "reason", "");
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

void GatewayAPI::set_challenge(HttpResponse& resp, std::string_view detail, bool no_credentials)
{
    if (no_credentials) {
        resp.set_header("WWW-Authenticate", "Bearer");
        return;
    }

    // RFC 6750 §3: error_description is %x20-21 / %x23-5B / %x5D-7E — printable
    // ASCII without the quote and the backslash. Escaping would put a backslash
    // in, which the grammar forbids too, so a detail outside the alphabet (a
    // localised message, a quote) is left out rather than mangled; the body
    // carries it anyway. The same choice as the go-platform host, so both 401s
    // of /api/v2 read alike.
    const bool describable = !detail.empty() &&
        std::all_of(detail.begin(), detail.end(), [](unsigned char c) {
            return c >= 0x20 && c <= 0x7E && c != '"' && c != '\\';
        });

    resp.set_header("WWW-Authenticate",
                    describable
                        ? fmt::format(R"(Bearer error="invalid_token", error_description="{}")", detail)
                        : std::string(R"(Bearer error="invalid_token")"));
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
        case Kind::malformed:      slug = "bad-request";   title = "Bad Request"; break;
        case Kind::forbidden:      slug = "forbidden";     title = "Forbidden"; break;
    }

    reply_problem(resp, status, slug, title, refusal.message, refusal.path);
}

void GatewayAPI::execute(const HttpRequest& req, std::shared_ptr<HttpConnection> conn,
                         const ExecContext& ctx, std::string_view method,
                         const std::string& payload, const ResultShaping& shaping)
{
    if (std::find(v1_routes_.begin(), v1_routes_.end(), req.path) != v1_routes_.end()) {
        execute_v1(req, std::move(conn), ctx, method, payload, shaping);
        return;
    }

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
        // Before the first reload the table holds only this worker's own
        // sockets: a path no prefix covers yet may well be served by an
        // instance of another worker — a fresh worker (a restart by the
        // master, SIGHUP) would answer 404 for a second or two. Not yet known
        // is 503 + Retry-After, like a route with nothing ready — under a slug
        // of its own, routes-loading: a client
        // branches on type, not on detail.
        if (covered || !table_loaded_)
            answer_problem(conn, ctx, 503, miss_slug(covered), "Service Unavailable", miss_detail(covered), req.path, request_id, /*retry_after=*/true);
        else
            answer_problem(conn, ctx, 404, "no-route", "Not Found", "no prefix covers the path", req.path, request_id);
        return;
    }
    forward_to(*inst, std::move(up), std::move(conn), ctx, std::move(request_id), 1);
}

// ─── API v1 routes (README § API v1 routes) ──────────────────────────────────

void GatewayAPI::execute_v1(const HttpRequest& req, std::shared_ptr<HttpConnection> conn,
                            const ExecContext& ctx, std::string_view method,
                            const std::string& payload, const ResultShaping& shaping)
{
    const std::string request_id = new_uuid();

    // A token is required, as on every /api/v2 path. The base step would take
    // a call without one to the unauthorised or the guest statement — the
    // guest one on the module's own service session; neither is offered here.
    if (ctx.auth_type == AuthType::none) {
        HttpResponse r;
        reply_problem(r, 401, "token-invalid", "Unauthorized", "a token is required", req.path, request_id,
                      /*no_credentials=*/true);
        conn->send_response(r);
        return;
    }

    // The v1 twin: the same statement under the /api/v1 path. "/api/v2" and
    // "/api/v1" are of one length; the path is a valid_prefix, so it has the head.
    HttpRequest v1 = req;
    v1.path.replace(0, 7, "/api/v1");

    ExecContext c = ctx;
    c.finish = [instance_path = req.path, request_id](HttpResponse& r, std::string_view source) {
        v1_finish(r, source, instance_path, request_id);
    };
    AppServer::execute(v1, std::move(conn), c, method, payload, shaping);
}

void GatewayAPI::v1_finish(HttpResponse& r, std::string_view source, std::string_view instance_path,
                           std::string_view request_id)
{
    // The pair of reply_refused for an answer of the base step: a success goes
    // as API v1 gives it, a refusal is problem+json like every /api/v2 answer.
    r.set_header("X-Request-Id", std::string(request_id));

    const int status = r.status_code();
    if (status < 400) return;
    // problem+json already (a refusal through reply_refused), or a body the
    // database chose itself (#raw): left as it is.
    const auto& hs = r.headers();
    const auto ct = std::find_if(hs.begin(), hs.end(), [](const auto& h) { return h.first == "Content-Type"; });
    if (ct == hs.end() || !ct->second.starts_with("application/json")) return;
    // A #raw answer may carry a 4xx/5xx status and a JSON type of its own:
    // its source is the database's {"#raw":{...}} — left as it is.
    if (source.starts_with("{")) {
        const auto j = json::parse(source, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("#raw")) return;
    }

    // The database's error envelope {"error":{"code","error","message"}}; for
    // a failed statement the source is the driver's text, which stays here.
    std::string message, id;
    check_pg_error(source, message, id);

    std::string type;
    if (!id.empty())
        type = "urn:apostol:error:" + id;       // the catalogue identifier, as the go-platform host gives it
    else if (status < 500)
        type = "urn:apostol:error:raise";       // a refusal without an identifier
    else
        type = "urn:apostol:gateway:internal";  // this side failed
    if (message.empty()) message = status >= 500 ? "internal error" : "the request was refused";

    const auto known = status_from_code(status);
    const std::string title = known ? std::string(status_text(*known)) : std::string("Error");

    const json body = {
        {"type",       type},
        {"title",      title},
        {"status",     status},
        {"detail",     message},
        {"instance",   instance_path},
        {"request_id", request_id},
        {"code",       id.empty() ? json(nullptr) : json(id)},
    };
    // Status and headers (the challenge of a 401, cookies) stay as the base set them.
    r.set_body(body.dump(), "application/problem+json");
}

std::string GatewayAPI::v1_route_claim(const std::vector<std::string>& prefixes) const
{
    for (const auto& route : v1_routes_)
        for (const auto& mine : prefixes)
            if (prefixes_overlap(route, mine))
                return fmt::format("prefix {} overlaps {}, served by the gateway as an API v1 route", mine, route);
    return {};
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

std::string_view GatewayAPI::miss_detail(bool covered)
{
    return covered ? "route exists, no instance is ready" : "routing table not loaded yet";
}

// Called only on a 503: covered → a route with nothing ready; not covered →
// the table has not been read yet, so "no route" is not known.
std::string_view GatewayAPI::miss_slug(bool covered)
{
    return covered ? "no-instance" : "routes-loading";
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
    kept.emplace_back("X-Gateway-Worker", self_);   // "<node>:<pid>" (README § Identity)

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
                {"owner_node",   inst.owner_node.empty() ? json(nullptr) : json(inst.owner_node)},
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
    relays_.clear();   // their connections are closing with the worker
    stopping_ = true;
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
#ifdef APOSTOL_PG_LISTEN_READY
        // A NOTIFY committed while the listener was down is lost; the server's
        // acknowledgement of LISTEN — the first and every re-subscription after
        // the pool replaced a lost listener — is the moment from which nothing
        // is lost any more. Re-read then instead of waiting reload_interval.
        db_.listen("gateway", [this](std::string_view, std::string_view payload) { on_gateway_notify(payload); },
                   [this](std::string_view) {
                       if (stopping_) return;   // heartbeat() is latched on stop, this callback is not
                       log_.notice("GatewayAPI: LISTEN gateway confirmed — reload");
                       next_reload_ = clock_t_::now() + std::chrono::seconds(reload_interval_);
                       mirror_reload();
                   });
        // The answer to a relayed command comes back on gateway_cmd: relay
        // nothing until this worker is listening there.
        db_.listen("gateway_cmd", [this](std::string_view, std::string_view payload) { on_cmd_notify(payload); },
                   [this](std::string_view) { cmd_listening_ = true; });
#else
        db_.listen("gateway", [this](std::string_view, std::string_view payload) { on_gateway_notify(payload); });
        db_.listen("gateway_cmd", [this](std::string_view, std::string_view payload) { on_cmd_notify(payload); });
        cmd_listening_ = true;   // no acknowledgement to wait for: an answer before LISTEN is a 504
#endif
        next_seen_   = now + std::chrono::seconds(heartbeat_interval_);
        // Until the first reload lands a miss is 503, not 404 (table_loaded_).
        // With the LISTEN hook the first reload is the one on its confirmation
        // — a snapshot taken after it misses no NOTIFY; the tick is the
        // fallback. Without it, a second: a snapshot taken before LISTEN is
        // answered would miss a row committed in between until reload_interval.
#ifdef APOSTOL_PG_LISTEN_READY
        next_reload_ = now + std::chrono::seconds(2);
#else
        next_reload_ = now + std::chrono::seconds(1);
#endif
    }
    if (now >= next_seen_)   { next_seen_   = now + std::chrono::seconds(heartbeat_interval_); mirror_seen(now); }
    if (now >= next_reload_) { next_reload_ = now + std::chrono::seconds(reload_interval_);    mirror_reload();  }
    if (mirror_busy_ && seconds_since(mirror_sent_, now) >= reload_interval_)
        mirror_warn("write", fmt::format("outstanding for {} s, {} more queued", seconds_since(mirror_sent_, now),
                                         mirror_queue_.size()));

    // Relayed commands not answered within k_relay_answer_s. Any answer that
    // came before wins, whether pg_notify has returned or not: its result can
    // be lost with the connection (the pool sends it again, PgRetry::if_lost) after the
    // command was committed and run.
    for (auto it = relays_.begin(); it != relays_.end();) {
        if (now - it->second.sent < std::chrono::seconds(k_relay_answer_s)) { ++it; continue; }
        const bool unsent = !it->second.notified;
        auto conn = std::move(it->second.http_conn);
        const std::string what = it->second.what;
        it = relays_.erase(it);
        if (unsent) {
            log_.warn("GatewayAPI: {}: not relayed — pg_notify has not returned in {} s", what, k_relay_answer_s);
            respond(conn, {503, {}, "database-unavailable", "Service Unavailable",
                           // Not "did not take": with PgRetry::if_lost a first send may
                           // have committed before the connection went, and its holder's
                           // answer may have gone with the database. Only this is known.
                           fmt::format("the database did not confirm the command in {} s, and no worker holding the socket answered",
                                       k_relay_answer_s)});
        } else {
            log_.warn("GatewayAPI: {}: relayed, no worker holding the socket answered in {} s", what, k_relay_answer_s);
            respond(conn, {504, {}, "upstream-timeout", "Gateway Timeout",
                           fmt::format("relayed; no worker holding the socket answered in {} s", k_relay_answer_s)});
        }
    }
    // A second past the deadline: until then a replay must still find its id.
    std::erase_if(cmd_seen_, [now](const auto& e) { return e.second + std::chrono::seconds(1) < now; });

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
                auto answer = std::move(it->second.answer);
                const std::string action = it->second.action;
                it = node->pending.erase(it);
                if (answer)
                    answer({504, {}, "upstream-timeout", "Gateway Timeout",
                            fmt::format("{} not answered in {} s", action, k_call_timeout_s)});
            } else {
                ++it;
            }
        }

        // suspect / offline by the clock, not by a counter (README § Instance states).
        auto* inst = find_instance(node->module, node->instance);
        if (!inst || !owns(*inst)) continue;
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

void GatewayAPI::mirror_exec(std::string sql, std::string what, PgQuery::ResultHandler on_result, std::string kind,
                             std::function<void()> on_fail)
{
    ++mirror_seq_;
    if (!kind.empty())
        std::erase_if(mirror_queue_, [&](const MirrorWrite& w) { return w.kind == kind; });
    mirror_queue_.push_back({std::move(sql), std::move(what), std::move(on_result), std::move(kind), std::move(on_fail)});
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
    // The pool queues a query while no connection is ready, and with
    // PgRetry::if_lost sends one cut off by a lost connection again —
    // every mirror write is an upsert, a state set or a read that ends in the
    // same state the second time (a register's repeat journals one extra
    // offline -> ready); on_exception is then for an SQL
    // error only. With the database
    // away this write simply waits; heartbeat() notices the age of
    // mirror_sent_ and says so.
    //
    // execute() itself can throw (epoll registration of a reconnect). The
    // write goes back to the head of the queue and the queue is released —
    // the next mirror_exec() retries it; on_fail is not called, the write is
    // not lost. Left busy, the mirror would stop for
    // the life of the worker: this used to be moot while any throw on a
    // frame ended the worker, and is not since the frame handler catches.
    // A throw after the pool has taken the query (add_io/modify_io failing
    // on ENOMEM and the like) would send this write twice; that is for
    // PgPool::execute to rule out, not for this queue.
    try {
        db_.execute(w.sql,
            [this, what, on_result = w.on_result, on_fail = w.on_fail](std::vector<PgResult> results) {
                if (on_result) {
                    try { on_result(std::move(results)); }
                    catch (const std::exception& e) { mirror_warn(what, e.what()); if (on_fail) on_fail(); }
                }
                mirror_next();
            },
            [this, what, on_fail = w.on_fail](std::string_view error) {
                mirror_warn(what, error);
                if (on_fail) on_fail();
                mirror_next();
            },
            true,    // quiet: seen and sweep are periodic, transitions are logged by set_state
            PgRetry::if_lost);
    } catch (const std::exception& e) {
        mirror_warn(what, e.what());
        mirror_queue_.push_front(std::move(w));
        mirror_busy_ = false;
    }
}

void GatewayAPI::mirror_upsert(const Instance& inst, std::string_view pre_reason, std::string_view reason, bool reassert)
{
    // One writer of a (module, instance) row at a time, across workers and
    // pods. Two registrations of one instance milliseconds apart on
    // two pods: the first INSERT is not committed yet, so the second
    // transaction's offline step sees no row and changes nothing, and its
    // ON CONFLICT waits for the first, then turns ready into ready — the
    // trigger is silent on an UPDATE that keeps the state, so neither the
    // journal nor any worker hears of the takeover, and the replaced socket
    // stays open until the next reload. Under the lock the second transaction
    // starts its statements after the first has committed: the offline step
    // sees the row, and the takeover is the offline + ready pair of NOTIFYs
    // the other workers act on. Transaction-scoped: released at the commit
    // that makes the row visible; '/' is not in a valid name, so two pairs
    // never make one key.
    std::string sql = fmt::format("SELECT pg_advisory_xact_lock(hashtextextended({}, 0));\n",
                                  pq_quote_literal(fmt::format("gateway.node/{}/{}", inst.module, inst.instance)));
    if (!pre_reason.empty())
        sql += fmt::format(
            "SELECT set_config('gateway.reason', {}, true);\n"
            "UPDATE gateway.node SET state = 'offline', updated = now() WHERE {} AND state <> 'offline';\n",
            pq_quote_literal(pre_reason), sql_ident(inst.module, inst.instance));
    sql += fmt::format(
        "SELECT set_config('gateway.reason', {}, true);\n"
        "INSERT INTO gateway.node (module, instance, version, address, prefixes, state, capacity, worker, node, registered, seen, updated)\n"
        "VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, now(), now(), now())\n"
        "ON CONFLICT (module, instance) DO UPDATE SET version = EXCLUDED.version, address = EXCLUDED.address,\n"
        "  prefixes = EXCLUDED.prefixes, state = EXCLUDED.state, capacity = EXCLUDED.capacity, worker = EXCLUDED.worker,\n"
        "  node = EXCLUDED.node, registered = {}, seen = now(), updated = now(){};",
        pq_quote_literal(reason),
        pq_quote_literal(inst.module), pq_quote_literal(inst.instance), pq_quote_literal(inst.version),
        pq_quote_literal(inst.address), sql_prefixes(inst.prefixes), pq_quote_literal(inst.state),
        inst.capacity, pid_, pq_quote_literal(node_),
        reassert ? "gateway.node.registered" : "now()",
        // A re-assert answers a snapshot; a register is the event itself and
        // overrides whatever the row says. `node` is set on both branches: a
        // binary that does not know the column leaves it as it was on its own
        // ON CONFLICT, so a row may carry another worker's node next to its
        // pid — the pair, never the pid alone, says whose it is.
        reassert ? fmt::format("\n  WHERE (gateway.node.node = {} AND gateway.node.worker = {}) OR gateway.node.state = 'offline'",
                               pq_quote_literal(node_), pid_)
                 : std::string{});
    // One simple-protocol query string: the statements run as ONE transaction
    // (no explicit BEGIN), so the transaction-local GUC reaches the trigger,
    // both NOTIFYs leave on the same commit, in this order, and the advisory
    // lock above is held to that commit — split the string and the lock goes
    // early. It relies on READ COMMITTED (each statement its own snapshot,
    // taken after the lock): under repeatable read the offline step would
    // still miss a row committed while it waited.
    mirror_exec(std::move(sql), fmt::format("upsert {}/{}", inst.module, inst.instance));
    inst.written = inst.upserted = mirror_seq_;
}

void GatewayAPI::mirror_state(const Instance& inst, std::string_view reason)
{
    mirror_exec(fmt::format(
        "SELECT set_config('gateway.reason', {}, true);\n"
        "UPDATE gateway.node SET state = {}, updated = now() WHERE {} AND node = {} AND worker = {};",
        pq_quote_literal(reason), pq_quote_literal(inst.state), sql_ident(inst.module, inst.instance),
        pq_quote_literal(node_), pid_),
        fmt::format("state {}/{} -> {}", inst.module, inst.instance, inst.state));
    inst.written = mirror_seq_;
    // `AND node AND worker`: the FIFO orders this worker's writes against
    // each other, not against another worker's. A transition queued here
    // before the NOTIFY of a takeover arrives, landing after the taker's
    // upsert, would otherwise re-claim the row — and the taker, reading a
    // foreign identity on its own live instance, would close its fresh
    // socket. Every caller either owns the row or has just read this
    // worker's (node, pid) from it. The pid alone would match the row of a
    // worker in another pod that happens to share it.
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
    mirror_exec(fmt::format("UPDATE gateway.node SET seen = now() WHERE node = {} AND worker = {} AND (module, instance) IN ({});",
                            pq_quote_literal(node_), pid_, rows),
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
    // Own rows — (node, pid) of this worker — are excluded: a stale `seen` of
    // ours is a row of a previous life of this identity, or a database that
    // was away; both are settled below, by socket, not by age. A row with
    // our pid and another node, or no node at all, is another worker's and
    // ages like any. The read carries the whole row as JSON so text[] never
    // has to be parsed here.
    const int stale_s = (offline_after_ + 1) * heartbeat_interval_;
    std::string sql = fmt::format(
        "SELECT set_config('gateway.reason', {}, true);\n"
        "UPDATE gateway.node SET state = 'offline', updated = now()\n"
        " WHERE state <> 'offline' AND (node, worker) IS DISTINCT FROM ({}, {}) AND seen < now() - make_interval(secs => {});\n"
        "SELECT coalesce(json_agg(n), '[]'::json)::text FROM (\n"
        "  SELECT module, instance, version, address, prefixes, state, capacity, worker, node,\n"
        "         extract(epoch FROM now() - seen)::int AS seen_s, extract(epoch FROM now() - registered)::int AS registered_s,\n"
        "         (extract(epoch FROM registered) * 1000000)::bigint AS registered_us\n"
        "    FROM gateway.node WHERE state <> 'offline') n;",
        pq_quote_literal(fmt::format("swept by worker {}: seen older than {} s", self_, stale_s)),
        pq_quote_literal(node_), pid_, stale_s);

    // The writes of this worker run in one queue, in order: one queued after
    // this reload lands after its snapshot. An own row the snapshot shows
    // differently from memory is then the row BEFORE that write, not a row
    // someone else got wrong — re-asserting it would only move `seen`
    // without a heartbeat (the stub caught it: ready -> suspect queued right
    // behind the reload). The write in the queue settles what it writes: an
    // upsert the whole row, a state write the state. A takeover does not wait
    // on it — a state write matches no row another worker holds.
    const std::uint64_t snapshot = mirror_seq_ + 1;   // the seq mirror_exec gives this reload
    mirror_exec(std::move(sql), "sweep+reload", [this, snapshot](std::vector<PgResult> results) {
        // A throw here is a failed reload: mirror_next warns and calls on_fail.
        if (results.empty() || results.back().rows() != 1) throw std::runtime_error("no result row");
        json rows = json::parse(results.back().value(0, 0));
        if (!rows.is_array()) throw std::runtime_error("not an array");

        const auto now = clock_t_::now();
        std::map<std::string, std::map<std::string, bool>> seen;   // (module, instance) present in the database

        // Who holds which prefix, as of this snapshot — the same answer on
        // every worker. Candidates: every live row of the snapshot —
        // an own socket's current row stands for the socket and is judged on
        // the row, as every other worker judges it — and the own sockets the
        // snapshot does not show yet (no row, a row older than our /register,
        // another worker's row), in place of their rows and after all of
        // them: an upsert still queued behind the reload is registered after
        // every row the snapshot holds. In the order of
        // `registered` — the database's clock, one for all workers; ties by
        // module, then instance — a candidate holds its prefixes unless one
        // overlaps a prefix already held by ANOTHER module: the earlier
        // registration keeps it, whichever worker holds which socket. An
        // instance the snapshot shows gone, or a prefix its row no longer
        // carries, holds nothing: it may have been handed over. A row failing
        // the other /register checks holds nothing either. mirror_refusal
        // checks cross-module overlap against `claims` while they are built
        // and for the length of the loop below. An own socket that holds
        // nothing is closed 1008 — the module waits as after a 409 and gets
        // the 409 when it comes back.
        struct Candidate {
            std::int64_t registered_us;
            std::string  module;
            std::string  instance;
            const json*  row;        // a snapshot row; nullptr — an own socket ahead of its row
            Instance*    own;        // the own socket behind it; nullptr — no socket here
        };
        constexpr std::int64_t k_unordered = std::numeric_limits<std::int64_t>::max();
        std::vector<Candidate> candidates;
        std::map<std::string, std::map<std::string, const json*>> row_of;
        for (const auto& row : rows) {
            if (!row.is_object() || !row.contains("module") || !row["module"].is_string() ||
                !row.contains("instance") || !row["instance"].is_string()) continue;
            row_of[row["module"].get<std::string>()][row["instance"].get<std::string>()] = &row;
        }
        const auto registered_us = [](const json& row) {
            auto it = row.find("registered_us");
            return it != row.end() && it->is_number_integer() ? it->get<std::int64_t>() : k_unordered;
        };
        // The snapshot predates our own /register queued behind the reload:
        // the row's `registered` is then older than ours (as in the loop).
        const auto stale = [&now](const json& row, const Instance& inst) {
            return row.contains("registered_s") && row["registered_s"].is_number() &&
                   now - std::chrono::seconds(row["registered_s"].get<int>()) < inst.registered - std::chrono::seconds(1);
        };
        std::map<std::string, std::map<std::string, Instance*>> own_row;   // own sockets with a current row
        for (auto& [mod, insts] : table_)
            for (auto& [name, inst] : insts) {
                if (!owns(inst) || !socket_of(mod, name)) continue;
                const json* row = row_of.count(mod) && row_of[mod].count(name) ? row_of[mod][name] : nullptr;
                if (row && row_is_me(*row) && !stale(*row, inst)) own_row[mod][name] = &inst;
                else candidates.push_back({k_unordered, mod, name, nullptr, &inst});
            }
        for (const auto& [mod, insts] : row_of)
            for (const auto& [name, row] : insts) {
                Instance* own = own_row.count(mod) && own_row[mod].count(name) ? own_row[mod][name] : nullptr;
                candidates.push_back({registered_us(*row), mod, name, row, own});
            }
        std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
            return std::tie(a.registered_us, a.module, a.instance) < std::tie(b.registered_us, b.module, b.instance);
        });

        std::map<std::string, std::vector<std::string>> claims;
        struct ClaimsScope {
            const std::map<std::string, std::vector<std::string>>*& slot;
            ~ClaimsScope() { slot = nullptr; }
        } claims_scope{reload_claims_};
        reload_claims_ = &claims;
        std::vector<std::pair<Instance*, std::string>> lost;
        for (const auto& c : candidates) {
            auto& to = claims[c.module];
            if (!c.row) {
                if (auto why = held_by(claims, c.module, c.own->prefixes); !why.empty())
                    lost.emplace_back(c.own, std::move(why));
                else
                    to.insert(to.end(), c.own->prefixes.begin(), c.own->prefixes.end());
            } else if (mirror_refusal(*c.row).empty()) {
                for (const auto& p : (*c.row)["prefixes"]) to.push_back(p.get<std::string>());
            } else if (c.own && (*c.row)["prefixes"].is_array()) {
                // Refused on the row: the socket goes only for a prefix of
                // another module — a refusal of another kind (a hand on the
                // row) leaves it to the re-assert below.
                std::vector<std::string> theirs;
                for (const auto& p : (*c.row)["prefixes"])
                    if (p.is_string()) theirs.push_back(p.get<std::string>());
                if (auto why = held_by(claims, c.module, theirs); !why.empty()) lost.emplace_back(c.own, std::move(why));
            }
        }
        for (auto& [inst, why] : lost) {
            // Written before the close, as every close this worker starts:
            // drop_node leaves a closing node's row alone.
            log_.warn("GatewayAPI: {}/{}: {}, registered earlier — closing 1008", inst->module, inst->instance, why);
            auto node = socket_of(inst->module, inst->instance);
            set_state(*inst, "offline", why);
            if (node) close_node(node, 1008, why);
        }
        for (const auto& row : rows) {
            if (!row.is_object() || !row.contains("module") || !row.contains("instance")) continue;
            const std::string module = row["module"].get<std::string>();
            const std::string instance = row["instance"].get<std::string>();
            const bool me = row_is_me(row);
            seen[module][instance] = true;

            auto* mine = find_instance(module, instance);
            if (mine && owns(*mine) && socket_of(module, instance)) {
                // The snapshot may predate our own /register queued behind
                // the reload: the row's `registered` is then older than ours
                // and its worker is stale. The upsert in the queue settles it.
                if (row.contains("registered_s") && row["registered_s"].is_number() &&
                    now - std::chrono::seconds(row["registered_s"].get<int>()) < mine->registered - std::chrono::seconds(1))
                    continue;
                if (!me) {
                    // A NOTIFY we missed: another worker holds the instance now
                    // — another (node, pid), a row with our pid under another
                    // node or none included. A row we would refuse is not a
                    // takeover — the socket stays.
                    if (mirror_admissible(row, "reload")) {
                        take_over(module, instance, row_identity(row));
                        mirror_apply(row, "reload");
                    }
                } else {
                    const bool same_route = row.value("address", "") == mine->address &&
                                            row.value("prefixes", json::array()) == json(mine->prefixes);
                    // A write of ours behind the snapshot settles the row: an
                    // upsert any of it, a state write the state alone.
                    const bool queued = mine->upserted > snapshot || (same_route && mine->written > snapshot);
                    if (!queued && (!same_route || row.value("state", "") != mine->state)) {
                        // Someone (the sweep, a database that was away, a hand
                        // with UPDATE on the table) has the row wrong: the
                        // socket is the truth, re-assert it. An address changed
                        // under our pid is silent — no state change, no NOTIFY —
                        // and the other workers would refuse or misroute it.
                        mirror_upsert(*mine, {}, "owner re-asserted", true);
                    }
                }
                continue;
            }
            if (me) {
                // The row names this worker (node and pid) and there is no
                // socket behind it: a previous life of this identity, or a
                // socket closed while the database was away. Close it in the
                // database. A row with our pid alone is not ours — another
                // pod's worker with the same pid, or a binary that writes no
                // node — and is mirrored below like any foreign row. An
                // offline of ours queued behind the snapshot (a socket closed
                // a moment ago, one that lost its prefix above) settles it.
                if (mine && owns(*mine) && mine->state == "offline" && mine->written > snapshot) continue;
                Instance gone;
                gone.module = module; gone.instance = instance; gone.state = "offline";
                mirror_state(gone, "no socket on worker");
                if (mine) { mine->state = "offline"; mine->last_heartbeat = now; }
                continue;
            }
            // A row the database holds but this worker refuses to route to
            // counts as absent: a mirror of it goes offline below.
            if (!mirror_apply(row, "reload")) seen[module].erase(instance);
        }

        for (auto& [mod, insts] : table_)
            for (auto& [name, inst] : insts) {
                const bool present = seen.count(mod) && seen[mod].count(name);
                if (present || inst.state == "offline") continue;
                if (owns(inst) && socket_of(mod, name)) {
                    // Missing or offline in the database while the socket is
                    // alive — the database was away when we wrote, or the sweep
                    // beat a `seen` that never arrived. Ours: re-assert, unless
                    // an upsert of ours is still behind the snapshot (a state
                    // write matches no row that is not there).
                    if (inst.upserted <= snapshot) mirror_upsert(inst, {}, "owner re-asserted", true);
                } else if (inst.source == Source::mirror) {
                    log_.notice("GatewayAPI: {}/{} {} -> offline (mirror: not in gateway.node)", mod, name, inst.state);
                    inst.state = "offline";
                    inst.last_heartbeat = now;
                }
            }
        if (!table_loaded_) {
            table_loaded_ = true;
            log_.notice("GatewayAPI: routing table loaded ({} rows) — a miss is 404 from now on", rows.size());
        }
    }, "reload", [this] {
        // The database answers, and answers every reload with an error (no
        // schema, no grant, a standby refusing the sweep): the table will not
        // load by waiting, and a 503 + Retry-After on every mistyped path
        // would have clients retry a 404 for good. A database that is simply
        // away does not come here — the pool holds the query until it is back.
        if (table_loaded_ || ++reload_failures_ < k_reload_failures) return;
        table_loaded_ = true;
        log_.warn("GatewayAPI: routing table not loaded after {} failed reloads — a miss is 404, routing own sockets only",
                  reload_failures_);
    });
}

std::string GatewayAPI::mirror_refusal(const json& row) const
{
    // A row that did not come through /register has had none of its checks:
    // pg_notify is open to any role with CONNECT, and a forged payload would
    // otherwise point /api/v2/* — Bearer tokens of users included — at an
    // address of its choosing, or under a prefix of another module (the
    // longest prefix wins). The /register rules, 400/403/409 there.
    const std::string module   = row.value("module", "");
    const std::string instance = row.value("instance", "");
    if (!valid_name(module) || !valid_name(instance)) return "bad module or instance name";

    if (!row.contains("address") || !row["address"].is_string()) return "no address";
    std::string host; uint16_t port = 0;
    const auto address = row["address"].get<std::string>();
    if (!parse_address(address, host, port)) return "address is not ipv4:port";
    if (!address_allowed(host)) return fmt::format("address {} is outside allowed_cidr", host);

    if (!row.contains("prefixes") || !row["prefixes"].is_array() || row["prefixes"].empty())
        return "prefixes must be a non-empty array";
    std::vector<std::string> prefixes;
    for (const auto& item : row["prefixes"]) {
        if (!item.is_string()) return "prefix must be a string";
        const auto s = item.get<std::string>();
        if (!valid_prefix(s)) return "bad prefix";
        for (const auto& have : prefixes)
            if (prefixes_overlap(have, s)) return fmt::format("prefixes overlap: {} and {}", have, s);
        prefixes.push_back(s);
    }
    if (auto claim = v1_route_claim(prefixes); !claim.empty()) return claim;
    const auto taken = [&](const std::string& mod, const std::vector<std::string>& theirs) -> std::string {
        for (const auto& t : theirs)
            for (const auto& mine : prefixes)
                if (prefixes_overlap(t, mine))
                    return fmt::format("prefix {} belongs to module {}", mine, mod);
        return {};
    };
    if (reload_claims_) {
        // A reload: the snapshot is the truth about who else is live. The
        // table may still hold an instance the snapshot shows offline or
        // gone (its NOTIFY lost) — checked against it, the new owner of a
        // handed-over prefix would be refused and the path left on the old
        // one for a whole reload_interval.
        return held_by(*reload_claims_, module, prefixes);
    }
    for (const auto& [mod, insts] : table_) {
        if (mod == module) continue;
        for (const auto& [name, inst] : insts) {
            if (inst.state == "offline") continue;
            if (auto why = taken(mod, inst.prefixes); !why.empty()) return why;
        }
    }
    return {};
}

bool GatewayAPI::mirror_admissible(const json& row, std::string_view why)
{
    const auto reason = mirror_refusal(row);
    if (reason.empty()) return true;
    mirror_refused(row, why, reason);
    return false;
}

void GatewayAPI::mirror_refused(const json& row, std::string_view why, std::string_view reason)
{
    // Throttled: a loop of forged pg_notify, or a bad row every reload on every
    // worker, must not become the same number of log lines. Names only when
    // valid — a forged one would otherwise write lines of its own into the log;
    // the reason carries no raw input for the same cause.
    const auto now = clock_t_::now();
    if (now < refused_warned_) { ++refused_quiet_; return; }
    refused_warned_ = now + std::chrono::seconds(reload_interval_);
    const std::string module   = row.value("module", "");
    const std::string instance = row.value("instance", "");
    const bool named = valid_name(module) && valid_name(instance);
    log_.warn("GatewayAPI: {}/{}: mirror row refused ({}): {}{}", named ? module : "?", named ? instance : "?",
              why, reason, refused_quiet_ ? fmt::format(" (+{} refused in the last {} s, not logged)",
                                                        refused_quiet_, reload_interval_) : std::string{});
    refused_quiet_ = 0;
}

bool GatewayAPI::mirror_apply(const json& row, std::string_view why)
{
    // A row of ANOTHER worker: whatever the database says is what this worker
    // routes by. Fields not in the NOTIFY payload (version, capacity) arrive
    // with the reload; the routing ones — address, prefixes, state — are in both.
    const std::string module   = row.value("module", "");
    const std::string instance = row.value("instance", "");
    const std::string state    = row.value("state", "");
    if (module.empty() || instance.empty() || state.empty()) return true;

    const auto now = clock_t_::now();
    auto* known = find_instance(module, instance);
    if (!known && state == "offline") return true;   // nothing to route to, nothing to forget
    if (const auto reason = mirror_refusal(row); !reason.empty()) {
        if (!known || state == "ready") { mirror_refused(row, why, reason); return false; }
        // Out of rotation only (offline, draining, suspect): the row routes
        // nothing, and refusing it would keep routing to the last good address
        // until the next reload. The state moves; address and prefixes stay.
        if (known->state != state) {
            log_.notice("GatewayAPI: {}/{} {} -> {} (mirror: {}, state only: {})", module, instance, known->state,
                        state, why, reason);
            known->state = state;
        }
        return true;
    }
    Instance& inst = known ? *known : table_[module][instance];
    const bool fresh = !known;
    const std::string from = fresh ? "(none)" : inst.state;
    inst.module   = module;
    inst.instance = instance;
    if (row.contains("version") && row["version"].is_string())    inst.version  = row["version"].get<std::string>();
    if (row.contains("capacity") && row["capacity"].is_number())  inst.capacity = row["capacity"].get<int>();
    inst.address = row["address"].get<std::string>();   // both checked by mirror_refusal
    parse_address(inst.address, inst.host, inst.port);
    inst.prefixes = row["prefixes"].get<std::vector<std::string>>();
    inst.owner_node   = node_of(row);
    inst.owner_worker = int_or(row, "worker", 0);
    inst.source       = Source::mirror;
    inst.conn_errors  = 0;   // the owner hears it; our passive count starts over
    inst.last_heartbeat = row.contains("seen_s") && row["seen_s"].is_number()
                            ? now - std::chrono::seconds(row["seen_s"].get<int>()) : now;
    if (fresh)
        inst.registered = row.contains("registered_s") && row["registered_s"].is_number()
                            ? now - std::chrono::seconds(row["registered_s"].get<int>()) : now;
    if (fresh || inst.state != state) {
        log_.notice("GatewayAPI: {}/{} {} -> {} (mirror: {}, worker {})", module, instance, from, state, why, row_identity(row));
        inst.state = state;
    }
    return true;
}

void GatewayAPI::take_over(const std::string& module, const std::string& instance, std::string_view by)
{
    // The database says another worker holds this instance now — the module
    // reconnected there (its old socket to us may still be open, or the
    // NOTIFY of our own offline is still in flight). The earlier socket is
    // the replaced one. registered=false so drop_node leaves the row, now
    // theirs, alone.
    if (auto node = socket_of(module, instance)) {
        log_.notice("GatewayAPI: {}/{}: replaced by worker {} — closing our socket fd={}", module, instance,
                    by, node->ws->fd());
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
    json msg = parse_bounded(std::string(payload));
    if (!msg.is_object()) return;

    const std::string module   = msg.value("module", "");
    const std::string instance = msg.value("instance", "");
    const std::string op       = msg.value("op", "");
    if (module.empty() || instance.empty()) return;
    if (op == "DELETE") msg["state"] = "offline";
    // `node` names the row's holder, `updated` is now() of the writing
    // transaction — neither is a version: two NOTIFYs are never ordered by it.

    auto* mine = find_instance(module, instance);
    const bool me = row_is_me(msg);
    if (mine && owns(*mine) && me && !socket_of(module, instance)) {
        // The echo of our own offline for a socket already gone: memory has
        // it; mirroring it back would re-stamp the row source=mirror.
        if (msg.value("state", "") == "offline") mine->state = "offline";
        return;
    }
    if (mine && owns(*mine) && socket_of(module, instance)) {
        // Our row. `node`/`worker` in the payload are the row's columns, not
        // the writer: our own writes come back with our identity, and so does
        // a sweep of our row by another worker. Neither is acted on here —
        // the socket is the truth, and the reload re-asserts a row the
        // database has wrong. Acting on the offline would fight the register
        // of a worker taking the instance over (its offline step keeps our
        // identity) — the ready that follows, with ITS identity, is the
        // takeover.
        //
        // And even that one is only a signal: the payload is whatever the
        // sender put there — pg_notify is open to any role with CONNECT, a
        // copy of a real address and prefix passes every check — and a stale
        // one (a takeover the module has since undone by reconnecting here)
        // is as good as forged. Closing a live socket on it would be the
        // forger's choice; the row is read back and the takeover acts on it.
        const std::string state = msg.value("state", "");
        if (!me && !state.empty() && state != "offline")
            mirror_reread(module, instance);
        return;
    }
    mirror_apply(msg, "notify");
}

void GatewayAPI::mirror_reread(const std::string& module, const std::string& instance)
{
    // In the FIFO: behind this worker's own queued writes, so the row read is
    // the one they leave. An upsert of ours queued after the read (the module
    // reconnected here while it was in flight) settles the row instead.
    const std::uint64_t snapshot = mirror_seq_ + 1;   // the seq mirror_exec gives this read
    mirror_exec(fmt::format(
        "SELECT coalesce((SELECT row_to_json(n)::text FROM (\n"
        "  SELECT module, instance, version, address, prefixes, state, capacity, worker, node,\n"
        "         extract(epoch FROM now() - seen)::int AS seen_s, extract(epoch FROM now() - registered)::int AS registered_s\n"
        "    FROM gateway.node WHERE {}) n), 'null');",
        sql_ident(module, instance)),
        fmt::format("re-read {}/{}", module, instance),
        [this, module, instance, snapshot](std::vector<PgResult> results) {
            if (results.empty() || results.back().rows() != 1) throw std::runtime_error("no result row");
            const json row = json::parse(results.back().value(0, 0));
            auto* mine = find_instance(module, instance);
            const bool held = mine && owns(*mine) && socket_of(module, instance);
            if (!row.is_object()) return;   // no row: ours is re-asserted by the reload, a mirror stays
            if (row_is_me(row)) {
                if (held)
                    log_.debug("GatewayAPI: {}/{}: NOTIFY of a takeover not confirmed by gateway.node — socket kept",
                                module, instance);
                return;
            }
            if (held) {
                if (mine->upserted > snapshot) return;   // our register behind the read settles the row
                // As in the reload: a holder registered before our socket is a
                // stale one (our own upsert failed, a late NOTIFY of its own),
                // not a takeover — a real one registers after us.
                if (row.contains("registered_s") && row["registered_s"].is_number() &&
                    clock_t_::now() - std::chrono::seconds(row["registered_s"].get<int>()) <
                        mine->registered - std::chrono::seconds(1))
                    return;
                const std::string state = row.value("state", "");
                if (state.empty() || state == "offline") return;   // not a takeover; the reload re-asserts ours
                if (mirror_admissible(row, "notify re-read")) {
                    take_over(module, instance, row_identity(row));
                    mirror_apply(row, "notify re-read");
                }
                return;
            }
            mirror_apply(row, "notify re-read");
        },
        // One outstanding re-read per instance: a burst of NOTIFYs — a loop of
        // forged ones included — costs one read, not one per message.
        fmt::format("reread {}/{}", module, instance));
}

bool GatewayAPI::row_is_me(const json& row) const
{
    auto it = row.find("node");
    return it != row.end() && it->is_string() && it->get<std::string>() == node_ && int_or(row, "worker", 0) == pid_;
}

std::string GatewayAPI::row_identity(const json& row)
{
    // For the log: `node` of a payload is whatever the sender wrote — nothing
    // of it may start a log line of its own, or run on for a page.
    auto it = row.find("node");
    std::string node = it != row.end() && it->is_string() ? it->get<std::string>().substr(0, 128) : std::string("(null)");
    for (auto& c : node)
        if (static_cast<unsigned char>(c) <= 0x20 || static_cast<unsigned char>(c) >= 0x7F) c = '?';
    return fmt::format("{}:{}", node, int_or(row, "worker", 0));
}

// ─── commands across workers (gateway_cmd) ───────────────────────────────────
//
// Wire form: "<64 hex of HMAC-SHA256>.<json>", the MAC over the json text as
// sent. pg_notify is open to any role with CONNECT and a LISTEN on the channel
// sees every payload: an unsigned command would let any of them drain a module
// (irreversible) or answer an operator in the module's name. A captured
// message replayed is stopped by its deadline and, within it, by its id.

namespace {

long long epoch_ms(clock_t_::time_point t)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

bool same_mac(std::string_view a, std::string_view b)
{
    if (a.size() != b.size()) return false;
    unsigned char d = 0;
    for (std::size_t i = 0; i < a.size(); ++i) d |= static_cast<unsigned char>(a[i] ^ b[i]);
    return d == 0;
}

bool is_command(std::string_view c) { return c == "ping" || c == "drain" || c == "reload"; }

// `from` / `by` of a signed message — "<node>:<pid>" of the worker that sent
// it; a number from a sender that predates the identity. For the log only:
// the answer is matched by the id. Signed, so not a forger's text — still
// cut to what a log line can carry.
std::string cmd_peer(const nlohmann::json& msg, const char* key)
{
    auto it = msg.find(key);
    if (it == msg.end()) return "?";
    std::string s = it->is_string() ? it->get<std::string>().substr(0, 128) : it->dump();
    for (auto& c : s)
        if (static_cast<unsigned char>(c) <= 0x20 || static_cast<unsigned char>(c) >= 0x7F) c = '?';
    return s;
}

} // namespace

std::string GatewayAPI::cmd_key() const
{
    const auto* app = providers_.find_default(audience_);
    if (!app || app->client_secret.empty()) return {};
    // Not the secret itself: it signs the audience's tokens too, and a key of
    // the channel's own keeps one kind of signature from passing for the other.
    return hmac_sha256_hex(app->client_secret, "apostol:gateway_cmd");
}

std::string GatewayAPI::cmd_sign(const json& body) const
{
    const auto key = cmd_key();
    if (key.empty()) return {};
    std::string text = body.dump(-1, ' ', false, json::error_handler_t::replace);
    return hmac_sha256_hex(key, text) + "." + text;
}

void GatewayAPI::cmd_notify(std::string payload, std::function<void()> on_sent,
                            std::function<void(std::string_view)> on_fail)
{
    // Not through mirror_exec: nothing orders a command against the mirror,
    // and a queue stalled behind the database would hold it past its deadline.
    // PgRetry::if_lost: a pg_notify cut off by a lost connection
    // may have committed — the holder may already have run the command. It is
    // sent again rather than reported: the holder drops a repeat by its id
    // (cmd_seen_) and a late one by its deadline, the requester takes the
    // first answer by id. on_fail is then for an SQL error only, when nothing
    // was committed.
    // execute() itself can throw (epoll registration of a reconnect): that is
    // on_fail too — close_node and drop_node answer their pending calls in a
    // loop, and a throw out of one cmd_answer would leave the rest unanswered.
    try {
        db_.execute(fmt::format("SELECT pg_notify('gateway_cmd', {})", pq_quote_literal(payload)),
            [on_sent](std::vector<PgResult>) { if (on_sent) on_sent(); },
            [on_fail](std::string_view error) { if (on_fail) on_fail(error); },
            /*quiet=*/true, PgRetry::if_lost);
    } catch (const std::exception& e) {
        if (on_fail) on_fail(e.what());
    }
}

void GatewayAPI::relay_command(const std::string& module, const std::string& instance, const std::string& command,
                               const json& p, std::shared_ptr<void> http_conn)
{
    const std::string id  = new_uuid();
    const auto        now = clock_t_::now();
    const std::string what = fmt::format("{}/{} {}", module, instance, command);
    const json body = {
        {"k", "cmd"}, {"id", id}, {"from", self_},
        {"module", module}, {"instance", instance}, {"command", command}, {"p", p},
        {"deadline", epoch_ms(now + std::chrono::seconds(k_relay_send_s))},
    };
    std::string payload = cmd_sign(body);
    if (payload.empty()) {
        // A configuration fault, not a transient one: no Retry-After.
        respond(http_conn, {500, {}, "internal", "Internal Server Error",
                            "the command channel has no key: the audience secret is not configured"});
        return;
    }
    if (payload.size() > k_notify_max_bytes) {
        respond(http_conn, {400, {}, "bad-request", "Bad Request",
                            fmt::format("body too large to relay: {} bytes signed, the channel carries {}",
                                        payload.size(), k_notify_max_bytes)});
        return;
    }
    relays_[id] = Relay{std::move(http_conn), what, now};
    log_.debug("GatewayAPI: {}: no socket on worker {} — relayed as {}", what, self_, id);
    cmd_notify(std::move(payload),
        [this, id]() { if (auto it = relays_.find(id); it != relays_.end()) it->second.notified = true; },
        [this, id](std::string_view error) {
            // An SQL error: the statement did not commit, nothing reached the
            // channel. (A lost connection is not reported here — cmd_notify
            // asks the pool to send the statement again, PgRetry::if_lost.)
            auto it = relays_.find(id);
            if (it == relays_.end()) return;
            auto conn = std::move(it->second.http_conn);
            const std::string w = it->second.what;
            relays_.erase(it);
            log_.warn("GatewayAPI: {}: not relayed: {}", w, error);
            respond(conn, {503, {}, "database-unavailable", "Service Unavailable", "the database refused the command"});
        });
}

void GatewayAPI::cmd_answer(const std::string& id, const std::string& to, const Answer& a)
{
    json body = {{"k", "reply"}, {"id", id}, {"by", self_}, {"status", a.status}};
    if (a.status == 200) body["body"] = a.body;
    else { body["slug"] = a.slug; body["title"] = a.title; body["detail"] = a.detail; }
    std::string payload = cmd_sign(body);
    if (payload.size() > k_notify_max_bytes) {
        body.erase("body");
        body["status"] = 502; body["slug"] = "upstream-error"; body["title"] = "Bad Gateway";
        body["detail"] = fmt::format("the module's answer is too large to relay: {} bytes signed, the channel carries {}",
                                     payload.size(), k_notify_max_bytes);
        payload = cmd_sign(body);
    }
    if (payload.empty()) return;   // no key: the requester will answer 504
    cmd_notify(std::move(payload), {}, [this, id, to](std::string_view error) {
        log_.warn("GatewayAPI: answer to command {} of worker {} not sent: {}", id, to, error);
    });
}

void GatewayAPI::cmd_refused(std::string_view reason)
{
    // Throttled as mirror_refused: any role can fill the channel.
    const auto now = clock_t_::now();
    if (now < cmd_warned_) { ++cmd_quiet_; return; }
    cmd_warned_ = now + std::chrono::seconds(reload_interval_);
    log_.warn("GatewayAPI: gateway_cmd message refused: {}{}", reason,
              cmd_quiet_ ? fmt::format(" (+{} refused in the last {} s, not logged)", cmd_quiet_, reload_interval_)
                         : std::string{});
    cmd_quiet_ = 0;
}

void GatewayAPI::on_cmd_notify(std::string_view payload)
{
    // Anything on the channel reaches here; nothing above catches.
    try { on_cmd_notify_(payload); }
    catch (const std::exception& e) { cmd_refused(fmt::format("unreadable ({})", e.what())); }
}

void GatewayAPI::on_cmd_notify_(std::string_view payload)
{
    // Every worker gets every message: the signature is checked first, and
    // nothing of an unsigned payload reaches the log.
    constexpr std::size_t mac_len = 64;
    if (payload.size() <= mac_len || payload[mac_len] != '.') { cmd_refused("not signed"); return; }
    const auto key = cmd_key();
    if (key.empty()) { cmd_refused("no key: the audience secret is not configured"); return; }
    const std::string_view text = payload.substr(mac_len + 1);
    if (!same_mac(payload.substr(0, mac_len), hmac_sha256_hex(key, text))) { cmd_refused("bad signature"); return; }

    const json msg = parse_bounded(std::string(text));
    if (!msg.is_object()) { cmd_refused("not an object"); return; }
    const std::string kind = msg.value("k", "");
    const std::string id   = msg.value("id", "");

    if (kind == "reply") {
        auto it = relays_.find(id);
        if (it == relays_.end()) return;   // another worker's, or given up on
        // Built before the relay is taken: a field of the wrong type throws,
        // and the request then still gets its 504 instead of nothing.
        Answer a{int_or(msg, "status", 502), msg.contains("body") ? msg["body"] : json::object(),
                 msg.value("slug", "upstream-error"), msg.value("title", "Bad Gateway"), msg.value("detail", "")};
        auto conn = std::move(it->second.http_conn);
        const std::string what = it->second.what;
        relays_.erase(it);
        log_.debug("GatewayAPI: {}: answered {} by worker {}", what, a.status, cmd_peer(msg, "by"));
        respond(conn, a);
        return;
    }
    if (kind != "cmd") { cmd_refused("unknown kind"); return; }

    const std::string module   = msg.value("module", "");
    const std::string instance = msg.value("instance", "");
    const std::string command  = msg.value("command", "");
    if (!valid_name(module) || !valid_name(instance) || !is_command(command) || id.empty() ||
        !msg.contains("p") || !msg["p"].is_object()) {
        cmd_refused("malformed command");
        return;
    }
    auto node = socket_of(module, instance);
    if (!node) return;   // held elsewhere, or by nobody: the requester answers 504

    const std::string from = cmd_peer(msg, "from");
    const auto now      = clock_t_::now();
    const long long due = msg.value("deadline", 0LL);
    if (epoch_ms(now) > due) {
        // Given up on by the requester: a late drain must not run after the
        // caller was told the command did not go.
        cmd_refused(fmt::format("{}/{} {} from worker {}: past its deadline by {} ms", module, instance, command,
                                from, epoch_ms(now) - due));
        return;
    }
    if (due > epoch_ms(now + std::chrono::seconds(k_relay_send_s + 60))) {
        cmd_refused(fmt::format("{}/{} {} from worker {}: deadline too far ahead", module, instance, command, from));
        return;
    }
    if (!cmd_seen_.emplace(id, clock_t_::time_point(std::chrono::milliseconds(due))).second) {
        // A replay — or the pool sending a pg_notify again after a lost
        // connection (PgRetry::if_lost in cmd_notify): the same message twice.
        cmd_refused(fmt::format("{}/{} {} from worker {}: id {} seen already (a replay, or a repeat after a lost connection)",
                                module, instance, command, from, id));
        return;
    }
    log_.notice("GatewayAPI: {}/{}: {} relayed by worker {}", module, instance, command, from);
    send_call(node, "/" + command, msg["p"], [this, id, from](const Answer& a) { cmd_answer(id, from, a); });
}

} // namespace apostol
