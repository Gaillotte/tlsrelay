#include "tlsrelay/relay/service.hpp"

#include "tlsrelay/logging.hpp"
#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/relay/transport.hpp"
#include "tlsrelay/tunnel/frame.hpp"
#include "tlsrelay/whitelist.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/strand.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <csignal>
#include <exception>
#include <filesystem>
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

// Répond une dernière trame (OPEN_FAIL, RESUME_FAIL...) puis ferme la connexion.
asio::awaitable<void> reject(std::shared_ptr<Stream> stream, std::string frame) {
    asio::steady_timer guard(co_await asio::this_coro::executor);
    guard.expires_after(1s);
    guard.async_wait([stream](std::error_code ec) {
        if (!ec) stream->close();
    });
    stream->queue(asio::buffer(frame));
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
#ifdef SIGHUP
        signals_.add(SIGHUP);  // rechargement de la PKI et de la liste blanche
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
    if (!config_.credentials) throw std::runtime_error("credentials.pki_root manquant");

    const auto result = pki::load_current_generation(config_.credentials->pki_root, *requirements);
    for (const auto& w : result.warnings) logging::config().warn("PKI : {} : {}", w.path, w.message);
    if (!result.generation) {
        std::string message = "PKI invalide dans " + config_.credentials->pki_root;
        for (const auto& e : result.errors) message += "\n  " + e.path + " : " + e.message;
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
    if (gen.cert) {
        logging::config().info("PKI : génération {} chargée, certificat {} valable jusqu'au {}", gen.name,
                               tls::subject_of(gen.cert.get()), tls::not_after_of(gen.cert.get()));
    } else {
        logging::config().info("PKI : génération {} chargée, AC attendue du serveur : {}", gen.name,
                               tls::subject_of(gen.trust_issuers.front().get()));
    }
}

Service::Contexts Service::build_contexts(const std::shared_ptr<const pki::Generation>& generation) const {
    Contexts c;
    const bool server = config_.mode == Mode::server;
    if (config_.ports.count(PortKind::tls)) {
        c.tls = server ? tls::Context::make_server(generation, false) : tls::Context::make_client(generation, false);
    }
    if (config_.ports.count(PortKind::mtls)) {
        c.mtls = server ? tls::Context::make_server(generation, true) : tls::Context::make_client(generation, true);
    }
    return c;
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
    for (const auto& w : result.warnings) logging::config().warn("PKI : {} : {}", w.path, w.message);
    auto refuse = [&](const std::string& why) {
        ++stats_.pki_reload_failures;
        logging::config().error("PKI : nouvelle génération refusée ({}) ; la génération {} reste en service", why,
                                previous->name);
    };
    if (!result.generation) {
        refuse("contrôles en échec");
        for (const auto& e : result.errors) logging::config().error("  {} : {}", e.path, e.message);
    } else if (result.generation->name == previous->name) {
        logging::config().info("PKI : génération {} inchangée", previous->name);
    } else if (auto problem = pki::rotation_guard(*previous, *result.generation, *requirements)) {
        refuse("garde-fou : " + *problem);
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
            logging::config().info("PKI : bascule vers la génération {}{} ; la génération {} reste utilisée par les "
                                   "connexions déjà ouvertes",
                                   gen.name,
                                   gen.cert ? " (certificat " + tls::subject_of(gen.cert.get()) + " valable jusqu'au " +
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
    logging::config().warn("PKI : fermeture immédiate des connexions établies avec une génération retirée");
    for (auto& ch : channels()) ch->close_if_retired(current.tls, current.mtls);
}

void Service::sweep_generations() {
    std::lock_guard lock(pki_mutex_);
    for (auto it = retired_.begin(); it != retired_.end();) {
        if (it->released()) {
            logging::config().info("PKI : génération {} libérée (plus aucune connexion)", it->name);
            it = retired_.erase(it);
        } else {
            ++it;
        }
    }
}

void Service::reload(bool kill_old) {
    asio::post(control_, [this, kill_old] {
        if (stopping_) return;
        logging::config().info("rechargement demandé{}", kill_old ? " (avec fermeture des anciennes générations)" : "");
        if (pki::requirements_for(config_)) {
            pki_pointer_ = read_pki_pointer();
            reload_pki(kill_old);
        }
        if (config_.mode == Mode::server) {
            whitelist_content_ = read_whitelist_file();
            reload_whitelist();
        }
    });
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

asio::awaitable<void> Service::watch() {
    const bool watch_pki = pki::requirements_for(config_) && config_.credentials && config_.credentials->watch;
    while (!stopping_) {
        watch_timer_.expires_after(options_.watch_interval);
        co_await watch_timer_.async_wait(use_tuple);
        if (stopping_) co_return;

        // Comparaison des contenus : indépendante de la précision des dates de modification.
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
        }
        sweep_generations();
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
    for (auto& ch : channels()) ch->revalidate();
}

int Service::run() {
    for (auto& port : ports_) {
        asio::co_spawn(port.acceptor.get_executor(), accept_loop(port), log_exceptions("acceptation"));
    }
    if (options_.handle_signals) asio::co_spawn(control_, wait_signals(), log_exceptions("signaux"));
    if (config_.mode == Mode::server || pki::requirements_for(config_)) {
        asio::co_spawn(control_, watch(), log_exceptions("surveillance"));
    }

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

        // Serveur : une connexion de transport peut aussi reprendre une session
        // existante ; la limite de canaux s'applique donc à OPEN (serve).
        auto& counter = config_.mode == Mode::server ? port.handshakes : port.active;
        if (counter.load() >= config_.limits.max_channels) {
            ++stats_.channels_rejected;
            std::error_code ignored;
            const auto peer = socket.remote_endpoint(ignored);
            logging::activity().warn("port={} limite de {} connexions atteinte : connexion de {} refusée",
                                     to_string(port.kind), config_.limits.max_channels,
                                     Endpoint{peer.address().to_string(), peer.port()}.to_string());
            socket.close(ignored);
            continue;
        }

        // Compté avant d'être enregistré : drain() ne peut pas manquer cette connexion.
        ++counter;
        const auto id = next_id_++;
        const auto strand = socket.get_executor();
        if (config_.mode == Mode::server) {
            asio::co_spawn(strand, serve(port, std::move(socket), id), log_exceptions("connexion de transport"));
            continue;
        }
        auto channel = std::make_shared<Channel>(id, strand, settings_for(port), stats_,
                                                 [this, &port](Channel& ch) { on_channel_closed(port, ch); });
        {
            std::lock_guard lock(channels_mutex_);
            channels_.emplace(id, channel);
        }
        channel->start_client(std::move(socket));
        // Arrêt demandé pendant l'acceptation : drain() a pu parcourir la liste avant l'enregistrement.
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
        stream = context ? std::make_shared<Stream>(std::move(socket), context) : std::make_shared<Stream>(std::move(socket));
    } catch (const std::exception& e) {
        // Par exemple, session TLS impossible à créer : on refuse cette connexion seulement.
        --port.handshakes;
        logging::activity().error("port={} connexion de {} refusée : {}", kind, peer.endpoint, e.what());
        co_return;
    }
    {
        std::lock_guard lock(channels_mutex_);
        handshakes_.emplace(id, stream);
    }
    // Quelle que soit l'issue, la connexion n'est plus « en attente » à la sortie.
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
            logging::activity().info("port={} handshake TLS refusé pair={} : {}", kind, peer.endpoint, failure);
            stream->close();
            co_return;
        }
        const auto subject = stream->peer_subject();
        logging::activity().debug("port={} TLS établi pair={} : {}, certificat du pair : {}", kind, peer.endpoint,
                                  stream->session_description(), subject.empty() ? "aucun" : subject);
    }

    auto transport = std::make_shared<Transport>(stream);
    const auto first = co_await read_frame(*transport, config_.limits.handshake_timeout);
    if (!first.frame) {
        if (first.protocol != tunnel::Decoder::Error::none) ++stats_.protocol_errors;
        logging::activity().info("port={} pair={} : pas de trame OPEN ou RESUME valide ({})", kind, peer.endpoint,
                                 first.protocol != tunnel::Decoder::Error::none ? transport->decoder.error_detail()
                                 : first.error == asio::error::timed_out        ? std::string("délai dépassé")
                                                                                : first.error.message());
        stream->close();
        co_return;
    }
    const auto& frame = *first.frame;
    const bool resume = frame.type == tunnel::FrameType::resume;
    if (frame.type != tunnel::FrameType::open && !resume) {
        ++stats_.protocol_errors;
        logging::activity().info("port={} pair={} : trame {} au lieu de OPEN ou RESUME", kind, peer.endpoint,
                                 tunnel::to_string(frame.type));
        co_await reject(stream, tunnel::encode_close(code(tunnel::CloseCode::protocol_error), "OPEN ou RESUME attendu"));
        co_return;
    }

    // Liste blanche : en mTLS, l'IP et le sujet du certificat doivent figurer dans la même entrée.
    if (port.kind == PortKind::mtls) {
        if (X509* cert = stream->peer_certificate()) peer.subject.reset(X509_NAME_dup(X509_get_subject_name(cert)));
    }
    const auto name = authorize(peer.address, port.kind, peer.subject.get());
    if (!name) {
        ++stats_.peers_rejected;
        logging::activity().info("port={} pair refusé par la liste blanche : ip={}{}", kind, peer.endpoint,
                                 peer.subject ? " sujet=" + tls::name_to_string(peer.subject.get()) : std::string());
        co_await reject(stream, resume ? tunnel::encode_resume_fail(code(tunnel::CloseCode::not_authorized))
                                       : tunnel::encode_open_fail(code(tunnel::CloseCode::not_authorized),
                                                                  "pair non autorisé"));
        co_return;
    }
    peer.name = *name;
    if (stopping_) {
        co_await reject(stream, resume ? tunnel::encode_resume_fail(code(tunnel::CloseCode::shutdown))
                                       : tunnel::encode_open_fail(code(tunnel::CloseCode::shutdown), "arrêt en cours"));
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
            // Le canal prend la connexion sur son propre strand.
            accepted = co_await asio::co_spawn(
                channel->executor(), channel->accept_resume(transport, request, std::move(peer), port.kind),
                asio::use_awaitable);
        } else {
            ++stats_.resume_failures;
            logging::activity().info("port={} reprise refusée pair={} : session {} inconnue", kind, endpoint, key);
        }
        if (!accepted) co_await reject(stream, tunnel::encode_resume_fail(code(tunnel::CloseCode::not_authorized)));
        co_return;
    }

    const auto open = tunnel::read_open(frame);
    std::string problem;
    if (open.version != tunnel::kVersion) {
        problem = "version de protocole " + std::to_string(open.version) + " non prise en charge";
    } else if (open.port != port.kind) {
        problem = "OPEN pour le port " + std::string(to_string(open.port)) + " reçu sur le port " + std::string(kind);
    }
    if (!problem.empty()) {
        ++stats_.protocol_errors;
        logging::activity().info("port={} pair={} : {}", kind, peer.endpoint, problem);
        co_await reject(stream, tunnel::encode_open_fail(code(tunnel::CloseCode::protocol_error), problem));
        co_return;
    }
    if (port.active.load() >= config_.limits.max_channels) {
        ++stats_.channels_rejected;
        logging::activity().warn("port={} limite de {} canaux atteinte : tunnel de {} refusé", kind,
                                 config_.limits.max_channels, peer.endpoint);
        co_await reject(stream, tunnel::encode_open_fail(code(tunnel::CloseCode::internal_error),
                                                         "limite de canaux atteinte"));
        co_return;
    }

    auto channel = std::make_shared<Channel>(id, co_await asio::this_coro::executor, settings_for(port), stats_,
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
        logging::activity().info("port={} pair={} : session {} déjà ouverte", kind, peer.endpoint, key);
        co_await reject(stream, tunnel::encode_open_fail(code(tunnel::CloseCode::protocol_error), "session déjà ouverte"));
        co_return;
    }
    channel->start_server(transport, open.session, std::move(peer));
    if (stopping_) channel->abort(CloseReason::shutdown);
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
#ifdef SIGHUP
        if (signal == SIGHUP) {
            logging::config().info("signal SIGHUP reçu : rechargement");
            reload(false);
            continue;
        }
#endif
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
    const auto& l = config_.limits;
    ChannelSettings s;
    s.side = config_.mode == Mode::client ? Side::client : Side::server;
    s.port = port.kind;
    s.idle_timeout = l.idle_timeout;
    s.handshake_timeout = l.handshake_timeout;
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
            // Relu à chaque connexion de transport : une renégociation utilise la génération courante.
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
    // Connexions de transport pas encore attribuées : fermées sur leur strand.
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
        }
    }
    --port.active;
}

}  // namespace tlsrelay::relay
