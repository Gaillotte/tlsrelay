#include "tlsrelay/relay/service.hpp"

#include "tlsrelay/logging.hpp"
#include "tlsrelay/version.hpp"
#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/pki/revocation.hpp"
#include "tlsrelay/openssl_info.hpp"
#include "tlsrelay/relay/transport.hpp"
#include "tlsrelay/system/notify.hpp"
#include "tlsrelay/tunnel/frame.hpp"
#include "tlsrelay/whitelist.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/strand.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <csignal>
#include <ctime>
#include <iomanip>
#include <exception>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#endif

namespace tlsrelay::relay {
namespace {

using asio::ip::tcp;
using namespace std::chrono_literals;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

// Completion handler for detached coroutines: an unexpected exception is
// logged instead of being ignored.
auto log_exceptions(const char* what) {
    return [what](const std::exception_ptr& e) {
        if (!e) return;
        try {
            std::rethrow_exception(e);
        } catch (const std::exception& ex) {
            logging::activity().error("{}: unexpected exception: {}", what, ex.what());
        }
    };
}

// Sends one last frame (OPEN_FAIL, RESUME_FAIL...) then closes the connection.
asio::awaitable<void> reject(std::shared_ptr<Stream> stream, std::string frame) {
    asio::steady_timer guard(co_await asio::this_coro::executor);
    guard.expires_after(1s);
    guard.async_wait([stream](std::error_code ec) {
        if (!ec) stream->close();
    });
    if (const auto ec = stream->queue(asio::buffer(frame))) {
        logging::activity().debug("rejection reply not sent: {}", ec.message());
    }
    co_await stream->shutdown_send();
    guard.cancel();
    stream->close();
}

std::uint16_t code(tunnel::CloseCode c) { return static_cast<std::uint16_t>(c); }

#ifdef _WIN32
using exclusive_address_use = asio::detail::socket_option::boolean<SOL_SOCKET, SO_EXCLUSIVEADDRUSE>;
#endif

}  // namespace

Service::Service(Config config, ServiceOptions options)
    : config_(std::move(config)),
      options_(std::move(options)),
      control_(asio::make_strand(io_)),
      signals_(control_),
      watch_timer_(control_) {
    for (const auto& [kind, port] : config_.ports) {
        if (config_.mode == Mode::client && !port.upstream) {
            throw std::invalid_argument("ports." + std::string(to_string(kind)) + ".upstream missing");
        }
    }
    if (config_.mode == Mode::server && !config_.destination) throw std::invalid_argument("destination missing");
    if (config_.mode == Mode::server && !config_.whitelist) throw std::invalid_argument("whitelist missing");
    if (config_.source_address) source_address_ = asio::ip::make_address(*config_.source_address);
    // Administration channel first: it serves as the instance lock.
    if (config_.admin.enabled) {
        const auto endpoint = admin::endpoint_for(config_);
        try {
            admin::Handler& handler = *this;
            admin_ = std::make_unique<admin::Server>(io_, endpoint, handler);
        } catch (const admin::AlreadyRunning&) {
            throw;
        } catch (const std::exception& e) {
            // Default location not accessible (console run without rights
            // on /run/tlsrelay): the relay works, without an administration channel.
            if (config_.admin.endpoint) throw;
            logging::config().warn("{}; administration channel disabled (set admin.endpoint to enable it)",
                                   e.what());
        }
        if (admin_) logging::config().info("administration channel: {}", admin_->endpoint());
    }
    load_pki();
    if (config_.mode == Mode::server) load_whitelist();

    for (const auto& [kind, port_config] : config_.ports) {
        auto& port = ports_.emplace_back(kind, port_config, tcp::acceptor(asio::make_strand(io_)));
        const tcp::endpoint ep(asio::ip::make_address(port_config.listen.host), port_config.listen.port);
        try {
            port.acceptor.open(ep.protocol());
#ifdef _WIN32
            port.acceptor.set_option(exclusive_address_use(true));
#else
            port.acceptor.set_option(tcp::acceptor::reuse_address(true));
#endif
            port.acceptor.bind(ep);
            port.acceptor.listen(asio::socket_base::max_listen_connections);
        } catch (const std::system_error& e) {
            throw std::system_error(e.code(), "cannot listen on " + port_config.listen.to_string() +
                                                  " (port " + std::string(to_string(kind)) + ")");
        }
        std::error_code ec;
        const auto bound = port.acceptor.local_endpoint(ec);
        logging::config().info("port={} listening on {}", to_string(kind),
                               Endpoint{bound.address().to_string(), bound.port()}.to_string());
    }

    if (options_.handle_signals) {
        signals_.add(SIGINT);
        signals_.add(SIGTERM);
#ifdef SIGHUP
        signals_.add(SIGHUP);  // reload of the PKI and the whitelist
#endif
#ifdef SIGUSR1
        signals_.add(SIGUSR1);  // reopen the log file
#endif
#ifdef SIGBREAK
        signals_.add(SIGBREAK);
#endif
    }
}

Service::~Service() = default;

void Service::load_pki() {
    const auto requirements = pki::requirements_for(config_);
    if (!requirements) return;
    if (!config_.credentials) throw std::runtime_error("credentials.pki_root missing");

    const auto result = pki::load_current_generation(config_.credentials->pki_root, *requirements);
    for (const auto& w : result.warnings) logging::config().warn("PKI: {}: {}", w.path, w.message);
    if (!result.generation) {
        std::string message = "invalid PKI in " + config_.credentials->pki_root;
        for (const auto& e : result.errors) message += "\n  " + e.path + ": " + e.message;
        throw std::runtime_error(message);
    }
    auto contexts = build_contexts(result.generation);
    const auto& gen = *result.generation;
    {
        std::lock_guard lock(pki_mutex_);
        generation_ = result.generation;
        contexts_ = std::move(contexts);
    }
    pki_pointer_ = read_pki_pointer();
    if (verifies_peers()) load_crl(gen, true);
    if (gen.cert) {
        logging::config().info("PKI: generation {} loaded, certificate {} valid until {}", gen.name,
                               tls::subject_of(gen.cert.get()), tls::not_after_of(gen.cert.get()));
    } else {
        logging::config().info("PKI: generation {} loaded, expected server CA: {}", gen.name,
                               tls::subject_of(gen.trust_issuers.front().get()));
    }
}

Service::Contexts Service::build_contexts(const std::shared_ptr<const pki::Generation>& generation) const {
    Contexts c;
    const bool server = config_.mode == Mode::server;
    if (config_.ports.count(PortKind::tls)) {
        c.tls = server ? tls::Context::make_server(generation, false, revocations_)
                       : tls::Context::make_client(generation, false, revocations_);
    }
    if (config_.ports.count(PortKind::mtls)) {
        c.mtls = server ? tls::Context::make_server(generation, true, revocations_)
                        : tls::Context::make_client(generation, true, revocations_);
    }
    return c;
}

bool Service::verifies_peers() const {
    const auto requirements = pki::requirements_for(config_);
    return requirements && requirements->trust;
}

std::optional<std::string> Service::read_crl_file() const {
    std::ifstream in(std::filesystem::path(config_.credentials->pki_root) / pki::kCrlFile, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

bool Service::load_crl(const pki::Generation& generation, bool initial) {
    const auto path = std::filesystem::path(config_.credentials->pki_root) / pki::kCrlFile;
    crl_content_ = read_crl_file();
    const auto previous = revocations_->get();
    if (!crl_content_) {
        if (previous) logging::config().warn("CRL: {} removed, no revocation checked any more", path.string());
        revocations_->set(nullptr);
        return true;
    }
    auto result = pki::load_revocations(path, generation);
    for (const auto& w : result.warnings) logging::config().warn("CRL: {}: {}", w.path, w.message);
    if (!result.list) {
        std::string message = "invalid CRL: " + path.string();
        for (const auto& e : result.errors) message += "\n  " + e.path + ": " + e.message;
        if (initial) throw std::runtime_error(message);
        ++stats_.crl_reload_failures;
        logging::config().error("{}; {}", message,
                                previous ? "the CRLs in force are kept" : "no revocation checked");
        return false;
    }
    std::size_t added = result.list->size();
    if (previous) {
        const auto before = previous->entries();
        added = 0;
        for (const auto& e : result.list->entries()) {
            if (std::find(before.begin(), before.end(), e) == before.end()) ++added;
        }
    }
    const auto count = result.list->size();
    const auto next = result.list->next_update();
    revocations_->set(std::move(result.list));
    logging::config().info("CRL {}: {} certificate(s) revoked{}, next update before {}",
                           initial ? "loaded" : "reloaded", count,
                           initial ? std::string() : " including " + std::to_string(added) + " new",
                           next.empty() ? std::string("?") : next);
    // Open channels: closed if their peer is revoked, except with revocation at the
    // next renegotiation (the following handshake will refuse it).
    const bool immediate = !config_.whitelist || config_.whitelist->revoke_mode == RevokeMode::immediate;
    if (!initial && added > 0 && immediate) {
        for (auto& ch : channels()) ch->close_if_revoked();
    }
    return true;
}

std::optional<std::string> Service::read_pki_pointer() const {
    std::ifstream in(std::filesystem::path(config_.credentials->pki_root) / "current", std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

void Service::reload_pki(bool kill_old) {
    const auto requirements = pki::requirements_for(config_);
    if (!requirements) return;

    std::shared_ptr<const pki::Generation> previous;
    {
        std::lock_guard lock(pki_mutex_);
        previous = generation_;
    }
    auto result = pki::load_current_generation(config_.credentials->pki_root, *requirements);
    for (const auto& w : result.warnings) logging::config().warn("PKI: {}: {}", w.path, w.message);
    auto refuse = [&](const std::string& why) {
        ++stats_.pki_reload_failures;
        logging::config().error("PKI: new generation refused ({}); generation {} stays in service", why,
                                previous->name);
    };
    if (!result.generation) {
        refuse("checks failed");
        for (const auto& e : result.errors) logging::config().error("  {}: {}", e.path, e.message);
    } else if (result.generation->name == previous->name) {
        logging::config().info("PKI: generation {} unchanged", previous->name);
    } else if (auto problem = pki::rotation_guard(*previous, *result.generation, *requirements)) {
        refuse("safeguard: " + *problem);
    } else {
        try {
            auto contexts = build_contexts(result.generation);
            {
                std::lock_guard lock(pki_mutex_);
                retired_.push_back({previous->name, contexts_.tls, contexts_.mtls});
                generation_ = result.generation;
                contexts_ = std::move(contexts);
            }
            ++stats_.pki_rotations;
            const auto& gen = *result.generation;
            if (verifies_peers()) load_crl(gen, false);
            logging::config().info("PKI: switched to generation {}{}; generation {} is still used by "
                                   "already open connections",
                                   gen.name,
                                   gen.cert ? " (certificate " + tls::subject_of(gen.cert.get()) + " valid until " +
                                                  tls::not_after_of(gen.cert.get()) + ")"
                                            : std::string(),
                                   previous->name);
        } catch (const std::exception& e) {
            refuse(e.what());
        }
    }
    if (kill_old) close_retired_generations();
    sweep_generations();
}

void Service::close_retired_generations() {
    Contexts current;
    {
        std::lock_guard lock(pki_mutex_);
        current = contexts_;
    }
    logging::config().warn("PKI: closing connections established with a retired generation immediately");
    for (auto& ch : channels()) ch->close_if_retired(current.tls, current.mtls);
}

void Service::sweep_generations() {
    std::lock_guard lock(pki_mutex_);
    for (auto it = retired_.begin(); it != retired_.end();) {
        if (it->released()) {
            logging::config().info("PKI: generation {} released (no connection left)", it->name);
            it = retired_.erase(it);
        } else {
            ++it;
        }
    }
}

void Service::reload(bool kill_old) {
    asio::co_spawn(control_, [this, kill_old]() -> asio::awaitable<void> { co_await reload_now(kill_old); },
                   log_exceptions("reload"));
}

asio::awaitable<std::string> Service::reload_now(bool kill_old) {
    if (stopping_) co_return "shutting down: reload ignored\n";
    logging::config().info("reload requested{}", kill_old ? " (closing old generations)" : "");
    std::string summary = reload_config();
    if (pki::requirements_for(config_)) {
        const auto before = current_generation();
        const auto failures = stats_.pki_reload_failures.load();
        pki_pointer_ = read_pki_pointer();
        reload_pki(kill_old);
        const auto after = current_generation();
        if (stats_.pki_reload_failures.load() != failures) {
            summary += "PKI: new generation refused (see the log); " + after + " stays in service\n";
        } else if (after != before) {
            summary += "PKI: switched from " + before + " to " + after + "\n";
        } else {
            summary += "PKI: generation " + after + " unchanged\n";
        }
        if (kill_old) summary += "PKI: connections of retired generations closed\n";
        if (verifies_peers()) {
            std::shared_ptr<const pki::Generation> gen;
            {
                std::lock_guard lock(pki_mutex_);
                gen = generation_;
            }
            if (!load_crl(*gen, false)) {
                summary += "CRL: invalid file (see the log), CRLs in force kept\n";
            } else if (const auto list = revocations_->get()) {
                summary += "CRL: " + std::to_string(list->size()) + " certificate(s) revoked\n";
            } else {
                summary += "CRL: none\n";
            }
        }
    }
    if (config_.mode == Mode::server) {
        whitelist_content_ = read_whitelist_file();
        if (reload_whitelist()) {
            summary += "whitelist: " + std::to_string(current_whitelist()->peers().size()) + " peer(s)\n";
        } else {
            summary += "whitelist: invalid file (see the log), whitelist in force kept\n";
        }
    }
    co_return summary;
}

// Rereads the configuration file: only the logging levels
// apply live; other changes are reported.
std::string Service::reload_config() {
    if (options_.config_path.empty()) return {};
    const auto result = load_config_file(options_.config_path);
    if (!result.config) {
        logging::config().error("configuration {} invalid: not reread", options_.config_path);
        for (const auto& e : result.errors) logging::config().error("  {}: {}", e.path, e.message);
        return "configuration: invalid file (see the log), not reread\n";
    }
    Config next = *result.config;
    if (!options_.stderr_log_replacement.empty() && next.logging.output == "stderr") {
        next.logging.output = options_.stderr_log_replacement;
    }
    const auto& log = next.logging;
    logging::set_level(logging::Category::activity, log.activity.value_or(log.level));
    logging::set_level(logging::Category::config, log.config.value_or(log.level));

    std::vector<std::string> changed;
    if (next.mode != config_.mode) changed.push_back("mode");
    if (next.instance != config_.instance) changed.push_back("instance");
    if (log.output != config_.logging.output || log.format != config_.logging.format) {
        changed.push_back("logging.output/format");
    }
    if (next.ports != config_.ports) changed.push_back("ports");
    if (next.source_address != config_.source_address) changed.push_back("source_address");
    if (next.destination != config_.destination) changed.push_back("destination");
    if (next.whitelist != config_.whitelist) changed.push_back("whitelist");
    if (next.credentials != config_.credentials) changed.push_back("credentials");
    if (next.limits != config_.limits) changed.push_back("limits");
    if (next.admin != config_.admin) changed.push_back("admin");
    config_.logging.level = log.level;
    config_.logging.activity = log.activity;
    config_.logging.config = log.config;

    std::string summary = "configuration: logging levels applied\n";
    if (!changed.empty()) {
        std::string list;
        for (const auto& c : changed) list += (list.empty() ? "" : ", ") + c;
        logging::config().warn("configuration changed ({}): restart required to apply it", list);
        summary += "configuration: restart required to apply " + list + "\n";
    }
    return summary;
}

std::string Service::current_generation() const {
    std::lock_guard lock(pki_mutex_);
    return generation_ ? generation_->name : std::string();
}

std::vector<std::string> Service::live_generations() const {
    std::lock_guard lock(pki_mutex_);
    std::vector<std::string> names;
    if (generation_) names.push_back(generation_->name);
    for (const auto& r : retired_) {
        if (!r.released()) names.push_back(r.name);
    }
    return names;
}

void Service::load_whitelist() {
    const auto& path = config_.whitelist->file;
    auto result = whitelist::Whitelist::load_file(path);
    for (const auto& w : result.warnings) logging::config().warn("whitelist: {}: {}", w.path, w.message);
    if (!result.whitelist) {
        std::string message = "invalid whitelist";
        for (const auto& e : result.errors) message += "\n  " + e.path + ": " + e.message;
        throw std::runtime_error(message);
    }
    whitelist_content_ = read_whitelist_file();
    logging::config().info("whitelist loaded from {}: {} peer(s)", path, result.whitelist->peers().size());
    std::lock_guard lock(whitelist_mutex_);
    whitelist_ = std::move(result.whitelist);
}

std::optional<std::string> Service::read_whitelist_file() const {
    std::ifstream in(config_.whitelist->file, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

std::shared_ptr<const whitelist::Whitelist> Service::current_whitelist() const {
    std::lock_guard lock(whitelist_mutex_);
    return whitelist_;
}

std::optional<std::string> Service::authorize(const asio::ip::address& address, PortKind port,
                                              const X509_NAME* subject) const {
    const auto wl = current_whitelist();
    const auto* peer = wl ? wl->authorize(address, port, subject) : nullptr;
    if (!peer) return std::nullopt;
    return peer->name;
}

asio::awaitable<void> Service::watch() {
    const bool watch_pki = pki::requirements_for(config_) && config_.credentials && config_.credentials->watch;
    while (!stopping_) {
        watch_timer_.expires_after(options_.watch_interval);
        co_await watch_timer_.async_wait(use_tuple);
        if (stopping_) co_return;

        // Content comparison: independent of the precision of modification times.
        if (config_.mode == Mode::server) {
            auto content = read_whitelist_file();
            if (content != whitelist_content_) {
                whitelist_content_ = std::move(content);
                reload_whitelist();
            }
        }
        if (watch_pki) {
            auto pointer = read_pki_pointer();
            if (pointer != pki_pointer_) {
                pki_pointer_ = std::move(pointer);
                reload_pki(false);
            }
            if (verifies_peers() && read_crl_file() != crl_content_) {
                std::shared_ptr<const pki::Generation> gen;
                {
                    std::lock_guard lock(pki_mutex_);
                    gen = generation_;
                }
                load_crl(*gen, false);
            }
        }
        sweep_generations();
    }
}

bool Service::reload_whitelist() {
    const auto& path = config_.whitelist->file;
    auto result = whitelist::Whitelist::load_file(path);
    for (const auto& w : result.warnings) logging::config().warn("whitelist: {}: {}", w.path, w.message);
    if (!result.whitelist) {
        logging::config().error("whitelist changed but invalid: the whitelist in force is kept");
        for (const auto& e : result.errors) logging::config().error("  {}: {}", e.path, e.message);
        return false;
    }
    const auto previous = current_whitelist();
    const auto changes = whitelist::diff(*previous, *result.whitelist);
    auto names = [](const std::vector<std::string>& v) {
        std::string out;
        for (const auto& n : v) out += (out.empty() ? "" : ", ") + n;
        return out.empty() ? std::string("none") : out;
    };
    logging::config().info("whitelist reloaded: {} peer(s); added: {}; removed: {}; changed: {}",
                           result.whitelist->peers().size(), names(changes.added), names(changes.removed),
                           names(changes.changed));
    {
        std::lock_guard lock(whitelist_mutex_);
        whitelist_ = std::move(result.whitelist);
    }
    if (config_.whitelist->revoke_mode != RevokeMode::immediate) return true;
    // Each channel checks its peer again and closes if it is no longer authorized.
    for (auto& ch : channels()) ch->revalidate();
    return true;
}

int Service::run() {
    for (auto& port : ports_) {
        asio::co_spawn(port.acceptor.get_executor(), accept_loop(port), log_exceptions("accept"));
    }
    if (options_.handle_signals) asio::co_spawn(control_, wait_signals(), log_exceptions("signals"));
    if (config_.mode == Mode::server || pki::requirements_for(config_)) {
        asio::co_spawn(control_, watch(), log_exceptions("watch"));
    }

    if (admin_) admin_->start();
    logging::config().info("service started mode={} instance={}", to_string(config_.mode), config_.instance);
    system::notify("READY=1\nSTATUS=in service");

    const unsigned count = options_.threads != 0 ? options_.threads : std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::thread> threads;
    threads.reserve(count - 1);
    for (unsigned i = 1; i < count; ++i) threads.emplace_back([this] { io_.run(); });
    io_.run();
    for (auto& t : threads) t.join();

    logging::config().info("service stopped");
    return 0;
}

void Service::request_stop() { request_stop(config_.limits.shutdown_timeout); }

void Service::request_stop(Duration timeout) {
    if (stopping_.exchange(true)) return;
    asio::co_spawn(control_, drain(timeout), log_exceptions("shutdown"));
}

void Service::request_abort() {
    stopping_ = true;
    if (aborting_.exchange(true)) return;
    asio::co_spawn(control_, drain(Duration::zero()), log_exceptions("immediate shutdown"));
}

std::optional<tcp::endpoint> Service::local_endpoint(PortKind kind) const {
    for (const auto& port : ports_) {
        if (port.kind != kind) continue;
        std::error_code ec;
        auto ep = port.acceptor.local_endpoint(ec);
        if (!ec) return ep;
    }
    return std::nullopt;
}

std::size_t Service::active_channels() const {
    std::size_t total = 0;
    for (const auto& port : ports_) total += port.active.load() + port.handshakes.load();
    return total;
}

asio::awaitable<void> Service::accept_loop(Port& port) {
    asio::steady_timer pause(port.acceptor.get_executor());
    for (;;) {
        auto [ec, socket] =
            co_await port.acceptor.async_accept(asio::any_io_executor(asio::make_strand(io_)), use_tuple);
        if (stopping_) {
            std::error_code ignored;
            socket.close(ignored);
            co_return;
        }
        if (ec) {
            if (ec == asio::error::operation_aborted || !port.acceptor.is_open()) co_return;
            // For example, no more descriptors available: back off.
            logging::activity().warn("port={} accept error: {}", to_string(port.kind), ec.message());
            pause.expires_after(100ms);
            co_await pause.async_wait(use_tuple);
            continue;
        }

        // Whitelist (server mode): the address must be authorized for this port,
        // before any handshake.
        if (config_.mode == Mode::server) {
            std::error_code rec;
            const auto remote = socket.remote_endpoint(rec);
            if (rec) {
                // Connection already closed by the peer (RST) before being handled.
                logging::activity().debug("port={} connection closed before being accepted: {}", to_string(port.kind),
                                          rec.message());
                std::error_code ignored;
                socket.close(ignored);
                continue;
            }
            const auto address = whitelist::normalize(remote.address());
            const auto wl = current_whitelist();
            if (!wl || !wl->admits(address, port.kind)) {
                ++stats_.peers_rejected;
                logging::activity().info("port={} connection from {} refused: address not in the whitelist",
                                         to_string(port.kind), address.to_string());
                std::error_code ignored;
                socket.close(ignored);
                continue;
            }
        }

        // Server: a transport connection can also resume an existing
        // session; the channel limit therefore applies to OPEN (serve).
        auto& counter = config_.mode == Mode::server ? port.handshakes : port.active;
        if (counter.load() >= config_.limits.max_channels) {
            ++stats_.channels_rejected;
            std::error_code ignored;
            const auto peer = socket.remote_endpoint(ignored);
            logging::activity().warn("port={} limit of {} connections reached: connection from {} refused",
                                     to_string(port.kind), config_.limits.max_channels,
                                     Endpoint{peer.address().to_string(), peer.port()}.to_string());
            socket.close(ignored);
            continue;
        }

        // Counted before being registered: drain() cannot miss this connection.
        ++counter;
        const auto id = next_id_++;
        const auto strand = socket.get_executor();
        if (config_.mode == Mode::server) {
            asio::co_spawn(strand, serve(port, std::move(socket), id), log_exceptions("transport connection"));
            continue;
        }
        auto channel = std::make_shared<Channel>(id, strand, settings_for(port), stats_,
                                                 [this, &port](Channel& ch) { on_channel_closed(port, ch); });
        {
            std::lock_guard lock(channels_mutex_);
            channels_.emplace(id, channel);
        }
        channel->start_client(std::move(socket));
        // Stop requested during accept: drain() may have walked the list before the registration.
        if (stopping_) channel->abort(CloseReason::shutdown);
    }
}

asio::awaitable<void> Service::serve(Port& port, tcp::socket socket, std::uint64_t id) {
    std::error_code ec;
    const auto remote = socket.remote_endpoint(ec);
    PeerIdentity peer;
    peer.address = whitelist::normalize(remote.address());
    peer.endpoint = ec ? std::string("?") : Endpoint{remote.address().to_string(), remote.port()}.to_string();
    socket.set_option(tcp::no_delay(true), ec);
    const auto kind = to_string(port.kind);

    std::shared_ptr<Stream> stream;
    try {
        std::shared_ptr<const tls::Context> context;
        if (port.kind != PortKind::plain) {
            std::lock_guard lock(pki_mutex_);
            context = port.kind == PortKind::mtls ? contexts_.mtls : contexts_.tls;
        }
        if (context) stream = std::make_shared<Stream>(std::move(socket), context);
        else stream = std::make_shared<Stream>(std::move(socket));
    } catch (const std::exception& e) {
        // For example, TLS session cannot be created: only this connection is refused.
        --port.handshakes;
        logging::activity().error("port={} connection from {} refused: {}", kind, peer.endpoint, e.what());
        co_return;
    }
    {
        std::lock_guard lock(channels_mutex_);
        handshakes_.emplace(id, stream);
    }
    // Whatever the outcome, the connection is no longer "pending" on exit.
    struct Done {
        Service& service;
        Port& port;
        std::uint64_t id;
        ~Done() {
            {
                std::lock_guard lock(service.channels_mutex_);
                service.handshakes_.erase(id);
            }
            --port.handshakes;
        }
    } done{*this, port, id};
    if (stopping_) {
        stream->close();
        co_return;
    }

    if (stream->is_tls()) {
        const auto failure = co_await secure(stream, config_.limits.handshake_timeout);
        if (!failure.empty()) {
            ++stats_.tls_handshake_failures;
            logging::activity().info("port={} TLS handshake refused peer={}: {}", kind, peer.endpoint, failure);
            stream->close();
            co_return;
        }
        const auto subject = stream->peer_subject();
        logging::activity().debug("port={} TLS established peer={}: {}, peer certificate: {}", kind, peer.endpoint,
                                  stream->session_description(), subject.empty() ? "none" : subject);
    }

    auto transport = std::make_shared<Transport>(stream);
    const auto first = co_await read_frame(*transport, config_.limits.handshake_timeout);
    if (!first.frame) {
        if (first.protocol != tunnel::Decoder::Error::none) ++stats_.protocol_errors;
        logging::activity().info("port={} peer={}: no valid OPEN or RESUME frame ({})", kind, peer.endpoint,
                                 first.protocol != tunnel::Decoder::Error::none ? transport->decoder.error_detail()
                                 : first.error == asio::error::timed_out        ? std::string("timed out")
                                                                                : first.error.message());
        stream->close();
        co_return;
    }
    const auto& frame = *first.frame;
    const bool resume = frame.type == tunnel::FrameType::resume;
    if (frame.type != tunnel::FrameType::open && !resume) {
        ++stats_.protocol_errors;
        logging::activity().info("port={} peer={}: {} frame instead of OPEN or RESUME", kind, peer.endpoint,
                                 tunnel::to_string(frame.type));
        co_await reject(stream, tunnel::encode_close(code(tunnel::CloseCode::protocol_error), "OPEN or RESUME expected"));
        co_return;
    }

    // Whitelist: with mTLS, the IP and the certificate subject must be in the same entry.
    if (port.kind == PortKind::mtls) {
        if (X509* cert = stream->peer_certificate()) peer.subject.reset(X509_NAME_dup(X509_get_subject_name(cert)));
    }
    const auto name = authorize(peer.address, port.kind, peer.subject.get());
    if (!name) {
        ++stats_.peers_rejected;
        logging::activity().info("port={} peer refused by the whitelist: ip={}{}", kind, peer.endpoint,
                                 peer.subject ? " subject=" + tls::name_to_string(peer.subject.get()) : std::string());
        // Frame computed outside the co_await: GCC 12 destroys twice the temporaries
        // of a conditional operator placed in the argument of a co_await.
        auto refusal = resume ? tunnel::encode_resume_fail(code(tunnel::CloseCode::not_authorized))
                              : tunnel::encode_open_fail(code(tunnel::CloseCode::not_authorized), "peer not authorized");
        co_await reject(stream, std::move(refusal));
        co_return;
    }
    peer.name = *name;
    if (stopping_) {
        auto refusal = resume ? tunnel::encode_resume_fail(code(tunnel::CloseCode::shutdown))
                              : tunnel::encode_open_fail(code(tunnel::CloseCode::shutdown), "shutting down");
        co_await reject(stream, std::move(refusal));
        co_return;
    }

    if (resume) {
        const auto request = tunnel::read_resume(frame);
        const auto key = tunnel::to_hex(request.session.data(), request.session.size());
        std::shared_ptr<Channel> channel;
        {
            std::lock_guard lock(channels_mutex_);
            if (auto it = sessions_.find(key); it != sessions_.end()) channel = it->second.lock();
        }
        const auto endpoint = peer.endpoint;
        bool accepted = false;
        if (channel) {
            // The channel takes the connection on its own strand.
            accepted = co_await asio::co_spawn(
                channel->executor(), channel->accept_resume(transport, request, std::move(peer), port.kind),
                asio::use_awaitable);
        } else {
            bool finished = false;
            {
                std::lock_guard lock(channels_mutex_);
                if (auto it = finished_.find(key); it != finished_.end() &&
                                                   it->second.expiry > std::chrono::steady_clock::now() &&
                                                   CRYPTO_memcmp(it->second.token.data(), request.token.data(),
                                                                 request.token.size()) == 0) {
                    finished_.erase(it);
                    finished = true;
                }
            }
            if (finished) {
                // Everything was delivered and acknowledged on this side: only the final acknowledgement was lost.
                logging::activity().debug("port={} resumption peer={}: session {} already finished normally", kind,
                                          endpoint, key);
                co_await reject(stream, tunnel::encode_resume_fail(code(tunnel::CloseCode::normal)));
                co_return;
            }
            ++stats_.resume_failures;
            logging::activity().info("port={} resumption refused peer={}: unknown session {}", kind, endpoint, key);
        }
        if (!accepted) co_await reject(stream, tunnel::encode_resume_fail(code(tunnel::CloseCode::not_authorized)));
        co_return;
    }

    const auto open = tunnel::read_open(frame);
    std::string problem;
    if (open.version != tunnel::kVersion) {
        problem = "protocol version " + std::to_string(open.version) + " not supported";
    } else if (open.port != port.kind) {
        problem = "OPEN for port " + std::string(to_string(open.port)) + " received on port " + std::string(kind);
    }
    if (!problem.empty()) {
        ++stats_.protocol_errors;
        logging::activity().info("port={} peer={}: {}", kind, peer.endpoint, problem);
        co_await reject(stream, tunnel::encode_open_fail(code(tunnel::CloseCode::protocol_error), problem));
        co_return;
    }
    if (port.active.load() >= config_.limits.max_channels) {
        ++stats_.channels_rejected;
        logging::activity().warn("port={} limit of {} channels reached: tunnel from {} refused", kind,
                                 config_.limits.max_channels, peer.endpoint);
        co_await reject(stream, tunnel::encode_open_fail(code(tunnel::CloseCode::internal_error),
                                                         "channel limit reached"));
        co_return;
    }

    // Never co_await in the middle of other arguments or of an initializer: GCC 12
    // then destroys some temporaries twice (Ubuntu 22.04 packages).
    const auto executor = co_await asio::this_coro::executor;
    auto channel = std::make_shared<Channel>(id, executor, settings_for(port), stats_,
                                             [this, &port](Channel& ch) { on_channel_closed(port, ch); });
    const auto key = tunnel::to_hex(open.session.data(), open.session.size());
    bool duplicate = false;
    {
        std::lock_guard lock(channels_mutex_);
        auto& slot = sessions_[key];
        duplicate = !slot.expired();
        if (!duplicate) {
            slot = channel;
            channels_.emplace(id, channel);
            ++port.active;
        }
    }
    if (duplicate) {
        ++stats_.protocol_errors;
        logging::activity().info("port={} peer={}: session {} already open", kind, peer.endpoint, key);
        co_await reject(stream, tunnel::encode_open_fail(code(tunnel::CloseCode::protocol_error), "session already open"));
        co_return;
    }
    channel->start_server(transport, open.session, std::move(peer));
    if (stopping_) channel->abort(CloseReason::shutdown);
}

asio::awaitable<void> Service::drain(Duration timeout) {
    system::notify("STOPPING=1\nSTATUS=shutting down");
    if (timeout == Duration::zero()) {
        logging::config().warn("immediate shutdown: {} active channel(s) cut", active_channels());
    } else {
        logging::config().info("shutdown requested: {} active channel(s), drain for at most {}",
                               active_channels(), format_duration(timeout));
    }

    for (auto& port : ports_) {
        asio::post(port.acceptor.get_executor(), [&port] {
            std::error_code ignored;
            port.acceptor.close(ignored);
        });
    }

    asio::steady_timer timer(control_);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (active_channels() > 0 && std::chrono::steady_clock::now() < deadline) {
        timer.expires_after(50ms);
        co_await timer.async_wait(use_tuple);
    }

    if (const auto remaining = active_channels(); remaining > 0) {
        if (timeout != Duration::zero()) {
            logging::config().info("drain timeout elapsed: closing {} channel(s)", remaining);
        }
        abort_all_channels();
        const auto hard_deadline = std::chrono::steady_clock::now() + 2s;
        while (active_channels() > 0 && std::chrono::steady_clock::now() < hard_deadline) {
            timer.expires_after(10ms);
            co_await timer.async_wait(use_tuple);
        }
    }

    watch_timer_.cancel();
    if (admin_) admin_->stop();
    // drain may run inside wait_signals (same strand): the
    // flag prevents the loop from re-arming after this cancellation.
    signals_done_ = true;
    std::error_code ignored;
    signals_.cancel(ignored);
    // If some channels could not finish, force the loop to stop.
    if (active_channels() > 0) io_.stop();
}

asio::awaitable<void> Service::wait_signals() {
    while (!signals_done_) {
        auto [ec, signal] = co_await signals_.async_wait(use_tuple);
        if (ec) co_return;
#ifdef SIGHUP
        if (signal == SIGHUP) {
            logging::config().info("signal SIGHUP received: reload");
            reload(false);
            continue;
        }
#endif
#ifdef SIGUSR1
        if (signal == SIGUSR1) {
            try {
                if (logging::reopen()) logging::config().info("signal SIGUSR1 received: log file reopened");
            } catch (const std::exception& e) {
                logging::config().error("cannot reopen the log file: {}", e.what());
            }
            continue;
        }
#endif
        if (!stopping_) {
            logging::config().info("signal {} received: graceful shutdown (a second signal forces an immediate shutdown)", signal);
            request_stop();
        } else {
            logging::config().warn("second signal {} received: immediate shutdown", signal);
            request_abort();
            co_return;
        }
    }
}

ChannelSettings Service::settings_for(const Port& port) const {
    const auto& l = config_.limits;
    ChannelSettings s;
    s.side = config_.mode == Mode::client ? Side::client : Side::server;
    s.port = port.kind;
    s.idle_timeout = l.idle_timeout;
    s.handshake_timeout = l.handshake_timeout;
    s.keepalive_interval = l.keepalive_interval;
    s.session_lifetime = l.session_lifetime;
    s.session_jitter = l.session_jitter;
    s.renegotiation_grace = l.renegotiation_grace;
    s.resume_buffer = l.resume_buffer;
    if (config_.mode == Mode::client) {
        s.dial.target = *port.config.upstream;
        s.dial.source = source_address_;
        s.dial.timeout = l.handshake_timeout;
        s.dial.attempts = 1;
        if (port.kind != PortKind::plain) {
            // Reread on each transport connection: a renegotiation uses the current generation.
            s.tls_context = [this, kind = port.kind] {
                std::lock_guard lock(pki_mutex_);
                return kind == PortKind::mtls ? contexts_.mtls : contexts_.tls;
            };
            s.server_name = port.config.server_name.value_or(port.config.upstream->host);
        }
    } else {
        s.authorizer = this;
        const auto& d = *config_.destination;
        s.dial.target = d.endpoint;
        s.dial.timeout = d.dial_timeout;
        s.dial.attempts = d.dial_retries;
        s.dial.backoff = d.dial_backoff;
    }
    return s;
}

std::vector<std::shared_ptr<Channel>> Service::channels() const {
    std::vector<std::shared_ptr<Channel>> result;
    std::lock_guard lock(channels_mutex_);
    for (const auto& [id, weak] : channels_) {
        if (auto ch = weak.lock()) result.push_back(std::move(ch));
    }
    return result;
}

void Service::abort_all_channels() {
    for (auto& ch : channels()) ch->abort(CloseReason::shutdown);
    // Transport connections not yet assigned: closed on their strand.
    std::vector<std::shared_ptr<Stream>> pending;
    {
        std::lock_guard lock(channels_mutex_);
        for (auto& [id, weak] : handshakes_) {
            if (auto s = weak.lock()) pending.push_back(std::move(s));
        }
    }
    for (auto& s : pending) asio::post(s->socket().get_executor(), [s] { s->close(); });
}

void Service::on_channel_closed(Port& port, Channel& channel) {
    {
        std::lock_guard lock(channels_mutex_);
        channels_.erase(channel.id());
        if (config_.mode == Mode::server) {
            const auto key = tunnel::to_hex(channel.session().data(), channel.session().size());
            if (auto it = sessions_.find(key); it != sessions_.end()) {
                auto current = it->second.lock();
                if (!current || current.get() == &channel) sessions_.erase(it);
            }
            const auto now = std::chrono::steady_clock::now();
            while (!finished_order_.empty() && finished_order_.front().first <= now) {
                if (auto it = finished_.find(finished_order_.front().second);
                    it != finished_.end() && it->second.expiry <= now) {
                    finished_.erase(it);
                }
                finished_order_.pop_front();
            }
            if (channel.close_reason() == CloseReason::normal && channel.resume_token()) {
                const auto expiry = now + config_.limits.renegotiation_grace;
                finished_[key] = FinishedSession{*channel.resume_token(), expiry};
                finished_order_.emplace_back(expiry, key);
            }
        }
    }
    --port.active;
}

// ---------------------------------------------------------------------------
// Administration channel

namespace {

// Process resources: resident memory (bytes) and open descriptors
// (handles on Windows). -1 if unavailable.
struct ProcessResources {
    long long resident_bytes = -1;
    long long descriptors = -1;
};

ProcessResources process_resources() {
    ProcessResources r;
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS counters{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof counters)) {
        r.resident_bytes = static_cast<long long>(counters.WorkingSetSize);
    }
    DWORD handles = 0;
    if (GetProcessHandleCount(GetCurrentProcess(), &handles)) r.descriptors = handles;
#else
    std::ifstream statm("/proc/self/statm");
    long long size = 0, resident = 0;
    if (statm >> size >> resident) r.resident_bytes = resident * ::sysconf(_SC_PAGESIZE);
    std::error_code ec;
    long long count = 0;
    for (auto it = std::filesystem::directory_iterator("/proc/self/fd", ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        ++count;
    }
    if (!ec) r.descriptors = count;
#endif
    return r;
}

std::string iso_time(std::chrono::system_clock::time_point tp) {
    const auto t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char out[32];
    (void)std::strftime(out, sizeof out, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return out;
}

std::string format_seconds(std::chrono::steady_clock::duration d) {
    auto total = std::chrono::duration_cast<std::chrono::seconds>(d).count();
    const auto days = total / 86400;
    total %= 86400;
    char out[48];
    (void)std::snprintf(out, sizeof out, "%lldd %02lld:%02lld:%02lld", static_cast<long long>(days),
                  static_cast<long long>(total / 3600), static_cast<long long>(total / 60 % 60),
                  static_cast<long long>(total % 60));
    return out;
}

// Escaping of a Prometheus label value.
std::string label(std::string_view value) {
    std::string out;
    for (const char c : value) {
        if (c == '\\' || c == '"') out += '\\';
        if (c == '\n') {
            out += "\\n";
            continue;
        }
        out += c;
    }
    return out;
}

constexpr const char* kCommands =
    "commands: status, channels, metrics, reload [--kill-old], stop [timeout], kill, log-level <level|category=level>, "
    "log-reopen, ping\n";

}  // namespace

std::string Service::status_text() const {
    std::ostringstream out;
    out << "instance: " << config_.instance << '\n'
        << "mode: " << to_string(config_.mode) << '\n'
        << "state: " << (stopping_ ? "shutting down" : "in service") << '\n'
#ifdef _WIN32
        << "pid: " << GetCurrentProcessId() << '\n'
#else
        << "pid: " << ::getpid() << '\n'
#endif
        << "started: " << iso_time(started_wall_) << " (for " << format_seconds(std::chrono::steady_clock::now() - started_)
        << ")\n"
        << "version: tlsrelay " << kVersion << ", " << openssl_runtime_version() << '\n';
    if (pki::requirements_for(config_)) {
        const auto live = live_generations();
        std::string retired;
        for (std::size_t i = 1; i < live.size(); ++i) retired += (retired.empty() ? "" : ", ") + live[i];
        out << "PKI generation: " << current_generation()
            << (retired.empty() ? std::string() : " (draining: " + retired + ")") << '\n';
    }
    if (verifies_peers()) {
        if (const auto crl = revocations_->get()) {
            out << "CRL: " << crl->size() << " certificate(s) revoked, next update before "
                << (crl->next_update().empty() ? std::string("?") : crl->next_update()) << '\n';
        } else {
            out << "CRL: none\n";
        }
    }
    if (config_.mode == Mode::server) {
        const auto wl = current_whitelist();
        out << "whitelist: " << (wl ? wl->peers().size() : 0) << " peer(s)\n";
    }
    out << "log: activity=" << to_string(logging::level(logging::Category::activity))
        << " config=" << to_string(logging::level(logging::Category::config)) << ", output " << logging::output()
        << '\n';
    for (const auto& port : ports_) {
        std::error_code ec;
        const auto ep = port.acceptor.local_endpoint(ec);
        out << "port " << to_string(port.kind) << ": "
            << (ec ? port.config.listen.to_string() : Endpoint{ep.address().to_string(), ep.port()}.to_string())
            << ", " << port.active.load() << " active channel(s)";
        if (config_.mode == Mode::server) out << ", " << port.handshakes.load() << " pending connection(s)";
        out << '\n';
    }
    const auto resources = process_resources();
    if (resources.resident_bytes >= 0) {
        out << "resources: " << resources.resident_bytes / (1024LL * 1024) << " MiB resident, " << resources.descriptors
#ifdef _WIN32
            << " handles\n";
#else
            << " descriptors\n";
#endif
    }
    out << "channels: " << stats_.channels_opened.load() << " opened, " << stats_.channels_closed.load()
        << " closed, " << stats_.channels_rejected.load() << " refused; renegotiations: "
        << stats_.renegotiations.load() << '\n';
    return out.str();
}

std::string Service::metrics_text() const {
    std::ostringstream out;
    const auto inst = "instance=\"" + label(config_.instance) + "\"";
    auto metric = [&](const char* name, const char* type, const char* help, const std::string& labels,
                      auto value) {
        out << "# HELP tlsrelay_" << name << ' ' << help << '\n'
            << "# TYPE tlsrelay_" << name << ' ' << type << '\n'
            << "tlsrelay_" << name << '{' << labels << "} " << value << '\n';
    };
    metric("info", "gauge", "tlsrelay and OpenSSL version.",
           inst + ",mode=\"" + std::string(to_string(config_.mode)) + "\",version=\"" + label(kVersion) +
               "\",openssl=\"" + label(openssl_runtime_version()) + "\"",
           1);
    metric("uptime_seconds", "gauge", "Time since startup.", inst,
           std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started_).count());

    const auto resources = process_resources();
    if (resources.resident_bytes >= 0) {
        metric("process_resident_memory_bytes", "gauge", "Resident memory of the process.", inst,
               resources.resident_bytes);
        metric("process_open_descriptors", "gauge", "Open descriptors (handles on Windows).", inst,
               resources.descriptors);
    }
    out << "# HELP tlsrelay_channels_active Open channels, per port.\n# TYPE tlsrelay_channels_active gauge\n";
    for (const auto& port : ports_) {
        out << "tlsrelay_channels_active{" << inst << ",port=\"" << to_string(port.kind) << "\"} "
            << port.active.load() << '\n';
    }
    if (pki::requirements_for(config_)) {
        out << "# HELP tlsrelay_pki_generation_info Current PKI generation.\n"
            << "# TYPE tlsrelay_pki_generation_info gauge\n"
            << "tlsrelay_pki_generation_info{" << inst << ",generation=\"" << label(current_generation()) << "\"} 1\n";
        metric("pki_generations_live", "gauge", "PKI generations still in use (current included).", inst,
               live_generations().size());
    }
    if (verifies_peers()) {
        const auto crl = revocations_->get();
        metric("crl_revoked_certificates", "gauge", "Revoked certificates listed by the CRLs in force.", inst,
               crl ? crl->size() : 0);
    }

    struct Counter {
        const char* name;
        const char* help;
        const std::atomic<std::uint64_t>& value;
    };
    const Counter counters[] = {
        {"channels_opened_total", "Channels opened.", stats_.channels_opened},
        {"channels_closed_total", "Channels closed.", stats_.channels_closed},
        {"channels_rejected_total", "Connections refused (max_channels limit).", stats_.channels_rejected},
        {"channels_idle_closed_total", "Channels closed for inactivity.", stats_.channels_idle_closed},
        {"dial_attempt_failures_total", "Failed outgoing connection attempts.", stats_.dial_attempt_failures},
        {"dial_failures_total", "Channels abandoned after all connection attempts.", stats_.dial_failures},
        {"tls_handshake_failures_total", "TLS handshakes refused or timed out.", stats_.tls_handshake_failures},
        {"peers_rejected_total", "Peers refused by the whitelist.", stats_.peers_rejected},
        {"certificates_revoked_total", "Channels closed after revocation of the peer certificate (CRL).",
         stats_.certificates_revoked},
        {"crl_reload_failures_total", "CRL files refused.", stats_.crl_reload_failures},
        {"peers_revoked_total", "Channels closed after removal of the peer from the whitelist.", stats_.peers_revoked},
        {"pki_rotations_total", "Switches to a new PKI generation.", stats_.pki_rotations},
        {"pki_reload_failures_total", "New PKI generations refused.", stats_.pki_reload_failures},
        {"renegotiations_total", "Successful session resumptions.", stats_.renegotiations},
        {"resume_failures_total", "Session resumptions refused or failed.", stats_.resume_failures},
        {"protocol_errors_total", "Malformed frames received.", stats_.protocol_errors},
        {"bytes_upstream_total", "Bytes relayed from the application to the destination (closed channels).",
         stats_.bytes_upstream},
        {"bytes_downstream_total", "Bytes relayed from the destination to the application (closed channels).",
         stats_.bytes_downstream},
    };
    for (const auto& c : counters) metric(c.name, "counter", c.help, inst, c.value.load());
    return out.str();
}

asio::awaitable<std::string> Service::channels_text() {
    std::ostringstream out;
    auto list = channels();
    std::sort(list.begin(), list.end(), [](const auto& a, const auto& b) { return a->id() < b->id(); });
    out << list.size() << " channel(s)\n";
    for (const auto& ch : list) {
        const auto info = co_await asio::co_spawn(ch->executor(), ch->describe(), asio::use_awaitable);
        out << "channel=" << info.id << " port=" << to_string(info.port) << " state=" << info.state
            << " session=" << info.session << " peer=" << info.peer;
        if (!info.generation.empty()) out << " generation=" << info.generation;
        out << " connection=" << info.transport << " age=" << format_duration(info.age)
            << " idle=" << format_duration(info.idle) << " up=" << info.bytes_up << "B"
            << " down=" << info.bytes_down << "B " << info.flow << "\n";
    }
    co_return out.str();
}

asio::awaitable<admin::Reply> Service::handle(admin::Request request, std::string caller) {
    std::string line = request.command;
    for (const auto& a : request.args) line += " " + a;
    // All administration operations are logged (SPEC §9).
    if (request.command == "status" || request.command == "ping" || request.command == "metrics" ||
        request.command == "channels") {
        logging::config().debug("administration: \"{}\" ({})", line, caller);
    } else {
        logging::config().info("administration: \"{}\" ({})", line, caller);
    }
    auto error = [](std::string message) { return admin::Reply{false, std::move(message) + "\n"}; };
    const auto& cmd = request.command;
    const auto argc = request.args.size();

    if (cmd == "ping" && argc == 0) co_return admin::Reply{true, "pong\n"};
    if (cmd == "status" && argc == 0) co_return admin::Reply{true, status_text()};
    if (cmd == "metrics" && argc == 0) co_return admin::Reply{true, metrics_text()};
    if (cmd == "channels" && argc == 0) {
        std::string text = co_await channels_text();
        co_return admin::Reply{true, std::move(text)};
    }
    if (cmd == "reload" && (argc == 0 || (argc == 1 && request.args[0] == "--kill-old"))) {
        std::string summary = co_await asio::co_spawn(control_, reload_now(argc == 1), asio::use_awaitable);
        co_return admin::Reply{true, std::move(summary)};
    }
    if (cmd == "stop" && argc <= 1) {
        Duration timeout = config_.limits.shutdown_timeout;
        if (argc == 1) {
            const auto parsed = parse_duration(request.args[0]);
            if (!parsed) co_return error("invalid timeout \"" + request.args[0] + "\" (examples: 10s, 1m)");
            timeout = *parsed;
        }
        if (stopping_) co_return admin::Reply{true, "shutdown already in progress\n"};
        request_stop(timeout);
        co_return admin::Reply{true, "shutting down: draining " + std::to_string(active_channels()) +
                                         " channel(s) for at most " + format_duration(timeout) + "\n"};
    }
    if (cmd == "kill" && argc == 0) {
        request_abort();
        co_return admin::Reply{true, "immediate shutdown in progress\n"};
    }
    if (cmd == "log-level" && argc == 1) {
        if (auto problem = logging::apply_level_spec(request.args[0]); !problem.empty()) co_return error(problem);
        logging::config().info("logging levels: activity={} config={}",
                               to_string(logging::level(logging::Category::activity)),
                               to_string(logging::level(logging::Category::config)));
        co_return admin::Reply{true, "levels: activity=" +
                                         std::string(to_string(logging::level(logging::Category::activity))) +
                                         " config=" + std::string(to_string(logging::level(logging::Category::config))) +
                                         "\n"};
    }
    if (cmd == "log-reopen" && argc == 0) {
        try {
            if (!logging::reopen()) co_return admin::Reply{true, "stderr output: nothing to reopen\n"};
        } catch (const std::exception& e) {
            co_return error(e.what());
        }
        logging::config().info("log file reopened");
        co_return admin::Reply{true, "log file reopened: " + logging::output() + "\n"};
    }
    co_return error("unknown command or arguments: \"" + line + "\"\n" + kCommands);
}

}  // namespace tlsrelay::relay
