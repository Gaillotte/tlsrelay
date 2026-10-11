#include "tlsrelay/relay/service.hpp"

#include "tlsrelay/logging.hpp"
#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/whitelist.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/strand.hpp>
#include <asio/use_awaitable.hpp>

#include <csignal>
#include <exception>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace tlsrelay::relay {
namespace {

using asio::ip::tcp;
using namespace std::chrono_literals;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

// Gestionnaire de fin des coroutines détachées : une exception non prévue est
// journalisée au lieu d'être ignorée.
auto log_exceptions(const char* what) {
    return [what](std::exception_ptr e) {
        if (!e) return;
        try {
            std::rethrow_exception(e);
        } catch (const std::exception& ex) {
            logging::activity().error("{} : exception inattendue : {}", what, ex.what());
        }
    };
}

#ifdef _WIN32
using exclusive_address_use = asio::detail::socket_option::boolean<SOL_SOCKET, SO_EXCLUSIVEADDRUSE>;
#endif

}  // namespace

Service::Service(Config config, ServiceOptions options)
    : config_(std::move(config)),
      options_(options),
      control_(asio::make_strand(io_)),
      signals_(control_),
      watch_timer_(control_) {
    for (const auto& [kind, port] : config_.ports) {
        if (config_.mode == Mode::client && !port.upstream) {
            throw std::invalid_argument("ports." + std::string(to_string(kind)) + ".upstream manquant");
        }
    }
    if (config_.mode == Mode::server && !config_.destination) throw std::invalid_argument("destination manquante");
    if (config_.mode == Mode::server && !config_.whitelist) throw std::invalid_argument("liste blanche manquante");
    if (config_.source_address) source_address_ = asio::ip::make_address(*config_.source_address);
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
            throw std::system_error(e.code(), "impossible d'écouter sur " + port_config.listen.to_string() +
                                                  " (port " + std::string(to_string(kind)) + ")");
        }
        std::error_code ec;
        const auto bound = port.acceptor.local_endpoint(ec);
        logging::config().info("port={} en écoute sur {}", to_string(kind),
                               Endpoint{bound.address().to_string(), bound.port()}.to_string());
    }

    if (options_.handle_signals) {
        signals_.add(SIGINT);
        signals_.add(SIGTERM);
#ifdef SIGBREAK
        signals_.add(SIGBREAK);
#endif
    }
}

Service::~Service() = default;

void Service::load_pki() {
    const auto requirements = pki::requirements_for(config_);
    if (!requirements) return;
    if (!config_.credentials) throw std::runtime_error("credentials.pki_root manquant");

    const auto result = pki::load_current_generation(config_.credentials->pki_root, *requirements);
    for (const auto& w : result.warnings) logging::config().warn("PKI : {} : {}", w.path, w.message);
    if (!result.generation) {
        std::string message = "PKI invalide dans " + config_.credentials->pki_root;
        for (const auto& e : result.errors) message += "\n  " + e.path + " : " + e.message;
        throw std::runtime_error(message);
    }
    const auto& gen = *result.generation;
    const bool server = config_.mode == Mode::server;
    if (config_.ports.count(PortKind::tls)) {
        tls_context_ = server ? tls::Context::make_server(result.generation, false)
                              : tls::Context::make_client(result.generation, false);
    }
    if (config_.ports.count(PortKind::mtls)) {
        mtls_context_ = server ? tls::Context::make_server(result.generation, true)
                               : tls::Context::make_client(result.generation, true);
    }
    if (gen.cert) {
        logging::config().info("PKI : génération {} chargée, certificat {} valable jusqu'au {}", gen.name,
                               tls::subject_of(gen.cert.get()), tls::not_after_of(gen.cert.get()));
    } else {
        logging::config().info("PKI : génération {} chargée, AC attendue du serveur : {}", gen.name,
                               tls::subject_of(gen.trust_issuer.get()));
    }
}

void Service::load_whitelist() {
    const auto& path = config_.whitelist->file;
    auto result = whitelist::Whitelist::load_file(path);
    for (const auto& w : result.warnings) logging::config().warn("liste blanche : {} : {}", w.path, w.message);
    if (!result.whitelist) {
        std::string message = "liste blanche invalide";
        for (const auto& e : result.errors) message += "\n  " + e.path + " : " + e.message;
        throw std::runtime_error(message);
    }
    whitelist_content_ = read_whitelist_file();
    logging::config().info("liste blanche chargée depuis {} : {} pair(s)", path, result.whitelist->peers().size());
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

asio::awaitable<void> Service::watch_whitelist() {
    while (!stopping_) {
        watch_timer_.expires_after(options_.whitelist_poll);
        co_await watch_timer_.async_wait(use_tuple);
        if (stopping_) co_return;

        // Comparaison du contenu : indépendante de la précision des dates de modification.
        auto content = read_whitelist_file();
        if (content == whitelist_content_) continue;
        whitelist_content_ = content;
        reload_whitelist();
    }
}

void Service::reload_whitelist() {
    const auto& path = config_.whitelist->file;
    auto result = whitelist::Whitelist::load_file(path);
    for (const auto& w : result.warnings) logging::config().warn("liste blanche : {} : {}", w.path, w.message);
    if (!result.whitelist) {
        logging::config().error("liste blanche modifiée mais invalide : la liste en vigueur est conservée");
        for (const auto& e : result.errors) logging::config().error("  {} : {}", e.path, e.message);
        return;
    }
    const auto previous = current_whitelist();
    const auto changes = whitelist::diff(*previous, *result.whitelist);
    auto names = [](const std::vector<std::string>& v) {
        std::string out;
        for (const auto& n : v) out += (out.empty() ? "" : ", ") + n;
        return out.empty() ? std::string("aucun") : out;
    };
    logging::config().info("liste blanche rechargée : {} pair(s) ; ajoutés : {} ; retirés : {} ; modifiés : {}",
                           result.whitelist->peers().size(), names(changes.added), names(changes.removed),
                           names(changes.changed));
    {
        std::lock_guard lock(whitelist_mutex_);
        whitelist_ = std::move(result.whitelist);
    }
    if (config_.whitelist->revoke_mode != RevokeMode::immediate) return;
    // Chaque canal vérifie de nouveau son pair et se ferme s'il n'est plus autorisé.
    std::vector<std::shared_ptr<Channel>> channels;
    {
        std::lock_guard lock(channels_mutex_);
        for (auto& [id, weak] : channels_) {
            if (auto ch = weak.lock()) channels.push_back(std::move(ch));
        }
    }
    for (auto& ch : channels) ch->revalidate();
}

int Service::run() {
    for (auto& port : ports_) {
        asio::co_spawn(port.acceptor.get_executor(), accept_loop(port), log_exceptions("acceptation"));
    }
    if (options_.handle_signals) asio::co_spawn(control_, wait_signals(), log_exceptions("signaux"));
    if (config_.mode == Mode::server) asio::co_spawn(control_, watch_whitelist(), log_exceptions("liste blanche"));

    logging::config().info("service démarré mode={} instance={}", to_string(config_.mode), config_.instance);

    const unsigned count = options_.threads != 0 ? options_.threads : std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::thread> threads;
    threads.reserve(count - 1);
    for (unsigned i = 1; i < count; ++i) threads.emplace_back([this] { io_.run(); });
    io_.run();
    for (auto& t : threads) t.join();

    logging::config().info("service arrêté");
    return 0;
}

void Service::request_stop() {
    if (stopping_.exchange(true)) return;
    asio::co_spawn(control_, drain(config_.limits.shutdown_timeout), log_exceptions("arrêt"));
}

void Service::request_abort() {
    stopping_ = true;
    if (aborting_.exchange(true)) return;
    asio::co_spawn(control_, drain(Duration::zero()), log_exceptions("arrêt immédiat"));
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
    for (const auto& port : ports_) total += port.active.load();
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
            // Par exemple, plus de descripteurs disponibles : on temporise.
            logging::activity().warn("port={} erreur d'acceptation : {}", to_string(port.kind), ec.message());
            pause.expires_after(100ms);
            co_await pause.async_wait(use_tuple);
            continue;
        }

        // Liste blanche (mode serveur) : l'adresse doit être autorisée pour ce port,
        // avant tout handshake.
        if (config_.mode == Mode::server) {
            std::error_code rec;
            const auto remote = socket.remote_endpoint(rec);
            const auto address = whitelist::normalize(remote.address());
            const auto wl = current_whitelist();
            if (rec || !wl || !wl->admits(address, port.kind)) {
                ++stats_.peers_rejected;
                logging::activity().info("port={} connexion de {} refusée : adresse absente de la liste blanche",
                                         to_string(port.kind), rec ? std::string("?") : address.to_string());
                std::error_code ignored;
                socket.close(ignored);
                continue;
            }
        }

        if (port.active.load() >= config_.limits.max_channels) {
            ++stats_.channels_rejected;
            std::error_code ignored;
            const auto peer = socket.remote_endpoint(ignored);
            logging::activity().warn("port={} limite de {} canaux atteinte : connexion de {} refusée",
                                     to_string(port.kind), config_.limits.max_channels,
                                     Endpoint{peer.address().to_string(), peer.port()}.to_string());
            socket.close(ignored);
            continue;
        }

        // Compté avant d'être enregistré : drain() ne peut pas manquer ce canal.
        ++port.active;
        const auto id = next_id_++;
        std::shared_ptr<Channel> channel;
        try {
            channel = std::make_shared<Channel>(id, std::move(socket), settings_for(port), stats_,
                                                [this, &port](std::uint64_t cid) { on_channel_closed(port, cid); });
        } catch (const std::exception& e) {
            // Par exemple, session TLS impossible à créer : on refuse cette connexion seulement.
            --port.active;
            logging::activity().error("port={} connexion refusée : {}", to_string(port.kind), e.what());
            continue;
        }
        {
            std::lock_guard lock(channels_mutex_);
            channels_.emplace(id, channel);
        }
        channel->start();
        // Arrêt demandé pendant l'acceptation : drain() a pu parcourir la liste avant l'enregistrement.
        if (stopping_) channel->abort(CloseReason::shutdown);
    }
}

asio::awaitable<void> Service::drain(Duration timeout) {
    if (timeout == Duration::zero()) {
        logging::config().warn("arrêt immédiat : {} canal(aux) actif(s) coupé(s)", active_channels());
    } else {
        logging::config().info("arrêt demandé : {} canal(aux) actif(s), drain pendant {} au plus",
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
            logging::config().info("délai de drain écoulé : fermeture de {} canal(aux)", remaining);
        }
        abort_all_channels();
        const auto hard_deadline = std::chrono::steady_clock::now() + 2s;
        while (active_channels() > 0 && std::chrono::steady_clock::now() < hard_deadline) {
            timer.expires_after(10ms);
            co_await timer.async_wait(use_tuple);
        }
    }

    watch_timer_.cancel();
    // drain peut s'exécuter à l'intérieur de wait_signals (même strand) : le
    // drapeau empêche la boucle de se réarmer après cette annulation.
    signals_done_ = true;
    std::error_code ignored;
    signals_.cancel(ignored);
    // Si des canaux n'ont pas pu se terminer, on force l'arrêt de la boucle.
    if (active_channels() > 0) io_.stop();
}

asio::awaitable<void> Service::wait_signals() {
    while (!signals_done_) {
        auto [ec, signal] = co_await signals_.async_wait(use_tuple);
        if (ec) co_return;
        if (!stopping_) {
            logging::config().info("signal {} reçu : arrêt propre (un second signal force l'arrêt immédiat)", signal);
            request_stop();
        } else {
            logging::config().warn("second signal {} reçu : arrêt immédiat", signal);
            request_abort();
            co_return;
        }
    }
}

ChannelSettings Service::settings_for(const Port& port) const {
    ChannelSettings s;
    s.port = port.kind;
    s.idle_timeout = config_.limits.idle_timeout;
    s.handshake_timeout = config_.limits.handshake_timeout;
    const auto& context = port.kind == PortKind::mtls ? mtls_context_ : tls_context_;
    const bool tls = port.kind != PortKind::plain;
    if (config_.mode == Mode::client) {
        s.dial.target = *port.config.upstream;
        s.dial.source = source_address_;
        s.dial.timeout = config_.limits.handshake_timeout;
        s.dial.attempts = 1;
        if (tls) {
            s.outbound_tls = context;
            s.server_name = port.config.server_name.value_or(port.config.upstream->host);
        }
    } else {
        s.authorizer = this;
        if (tls) s.inbound_tls = context;
        const auto& d = *config_.destination;
        s.dial.target = d.endpoint;
        s.dial.timeout = d.dial_timeout;
        s.dial.attempts = d.dial_retries;
        s.dial.backoff = d.dial_backoff;
    }
    return s;
}

void Service::abort_all_channels() {
    std::vector<std::shared_ptr<Channel>> channels;
    {
        std::lock_guard lock(channels_mutex_);
        for (auto& [id, weak] : channels_) {
            if (auto ch = weak.lock()) channels.push_back(std::move(ch));
        }
    }
    for (auto& ch : channels) ch->abort(CloseReason::shutdown);
}

void Service::on_channel_closed(Port& port, std::uint64_t id) {
    {
        std::lock_guard lock(channels_mutex_);
        channels_.erase(id);
    }
    --port.active;
}

}  // namespace tlsrelay::relay
