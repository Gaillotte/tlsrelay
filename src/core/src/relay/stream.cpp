#include "tlsrelay/relay/stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/ssl/error.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <openssl/err.h>

namespace tlsrelay::relay {
namespace {

using asio::ip::tcp;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);
// Un enregistrement TLS fait au plus 16 Kio de données plus l'en-tête et l'étiquette.
constexpr std::size_t kTlsBufferSize = 16 * 1024 + 512;

asio::awaitable<bool> cancelled() {
    auto state = co_await asio::this_coro::cancellation_state;
    co_return state.cancelled() != asio::cancellation_type::none;
}

}  // namespace

Stream::Stream(tcp::socket socket) : socket_(std::move(socket)), flush_done_(socket_.get_executor()) {}

Stream::Stream(tcp::socket socket, std::shared_ptr<const tls::Context> context, const std::string& server_name)
    : socket_(std::move(socket)),
      context_(std::move(context)),
      ssl_(context_->new_session(server_name)),
      read_buffer_(kTlsBufferSize),
      write_buffer_(kTlsBufferSize),
      flush_done_(socket_.get_executor()) {
    network_in_ = BIO_new(BIO_s_mem());
    network_out_ = BIO_new(BIO_s_mem());
    // BIO vide : « réessayer plus tard » plutôt que fin de fichier.
    BIO_set_mem_eof_return(network_in_, -1);
    SSL_set_bio(ssl_.get(), network_in_, network_out_);
    tls::set_failure_sink(ssl_.get(), &failure_reason_);
    if (context_->is_server()) SSL_set_accept_state(ssl_.get());
    else SSL_set_connect_state(ssl_.get());
}

Stream::~Stream() = default;

asio::awaitable<std::error_code> Stream::handshake() {
    if (!ssl_) co_return std::error_code{};
    for (;;) {
        ERR_clear_error();
        const int ret = SSL_do_handshake(ssl_.get());
        const int err = ret == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl_.get(), ret);
        // Envoie ce qu'OpenSSL a produit, y compris une alerte en cas d'échec.
        const auto flush_ec = co_await flush();
        if (err == SSL_ERROR_NONE) {
            if (flush_ec) co_return flush_ec;
            break;
        }
        if (err == SSL_ERROR_WANT_READ) {
            if (flush_ec) co_return flush_ec;
            if (auto ec = co_await fill()) {
                failure_reason_ = ec == asio::error::eof ? "connexion fermée par le pair pendant le handshake"
                                                          : "erreur réseau pendant le handshake : " + ec.message();
                co_return ec;
            }
            continue;
        }
        const long verify = SSL_get_verify_result(ssl_.get());
        if (verify != X509_V_OK && failure_reason_.empty()) {
            failure_reason_ = std::string("certificat du pair refusé : ") + X509_verify_cert_error_string(verify);
        }
        auto ec = tls_error();
        if (failure_reason_.empty()) failure_reason_ = ec.message();
        co_return ec;
    }

    if (auto problem = context_->check_peer(ssl_.get()); !problem.empty()) {
        failure_reason_ = std::move(problem);
        co_return asio::error::access_denied;
    }
    co_return std::error_code{};
}

asio::awaitable<std::pair<std::error_code, std::size_t>> Stream::read_some(asio::mutable_buffer buffer) {
    if (!ssl_) {
        auto [ec, n] = co_await socket_.async_read_some(buffer, use_tuple);
        co_return std::pair{ec, n};
    }
    for (;;) {
        ERR_clear_error();
        std::size_t n = 0;
        const int ret = SSL_read_ex(ssl_.get(), buffer.data(), buffer.size(), &n);
        const int err = ret == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl_.get(), ret);
        // La lecture peut produire des messages à envoyer (messages post-handshake).
        // Si un envoi est déjà en cours, il les emportera : la lecture ne doit
        // jamais attendre l'écriture (un pair qui ne lit plus bloquerait sinon
        // aussi la réception de ses propres trames).
        if (BIO_ctrl_pending(network_out_) > 0 && !flushing_) {
            if (auto ec = co_await flush()) co_return std::pair{ec, std::size_t{0}};
        }
        if (err == SSL_ERROR_NONE) co_return std::pair{std::error_code{}, n};
        if (err == SSL_ERROR_ZERO_RETURN) co_return std::pair{std::error_code(asio::error::eof), std::size_t{0}};
        if (err == SSL_ERROR_WANT_READ) {
            if (auto ec = co_await fill()) {
                // Fin TCP sans close_notify : flux tronqué, et non fin propre.
                if (ec == asio::error::eof) ec = asio::ssl::error::stream_truncated;
                co_return std::pair{ec, std::size_t{0}};
            }
            continue;
        }
        co_return std::pair{tls_error(), std::size_t{0}};
    }
}

std::error_code Stream::queue(asio::const_buffer buffer) {
    if (!ssl_) {
        plain_out_.append(static_cast<const char*>(buffer.data()), buffer.size());
        return {};
    }
    ERR_clear_error();
    std::size_t written = 0;
    // BIO mémoire : l'écriture est toujours complète, l'envoi réel se fait dans flush().
    if (SSL_write_ex(ssl_.get(), buffer.data(), buffer.size(), &written) != 1 || written != buffer.size()) {
        return tls_error();
    }
    return {};
}

asio::awaitable<std::error_code> Stream::write(asio::const_buffer buffer) {
    if (auto ec = queue(buffer)) co_return ec;
    co_return co_await flush();
}

bool Stream::export_keying_material(std::string_view label, const std::uint8_t* context, std::size_t context_size,
                                    std::uint8_t* out, std::size_t out_size) const {
    if (!ssl_) return false;
    return SSL_export_keying_material(ssl_.get(), out, out_size, label.data(), label.size(), context, context_size,
                                      1) == 1;
}

asio::awaitable<std::error_code> Stream::shutdown_send() {
    std::error_code ec;
    if (ssl_) {
        ERR_clear_error();
        // Premier appel : envoie close_notify sans attendre celui du pair.
        SSL_shutdown(ssl_.get());
        ERR_clear_error();
        ec = co_await flush();
    }
    std::error_code ignored;
    socket_.shutdown(tcp::socket::shutdown_send, ignored);
    co_return ec;
}

void Stream::close() {
    std::error_code ignored;
    socket_.close(ignored);
    flush_done_.cancel();
}

std::string Stream::session_description() const {
    if (!ssl_) return "clair";
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_.get());
    return std::string(SSL_get_version(ssl_.get())) + " " + (cipher ? SSL_CIPHER_get_name(cipher) : "?");
}

X509* Stream::peer_certificate() const { return ssl_ ? SSL_get0_peer_certificate(ssl_.get()) : nullptr; }

std::string Stream::peer_subject() const {
    if (!ssl_) return {};
    X509* peer = SSL_get0_peer_certificate(ssl_.get());
    return peer ? tls::subject_of(peer) : std::string();
}

asio::awaitable<std::error_code> Stream::flush() {
    // Une seule écriture à la fois sur la socket : on attend la fin de l'envoi
    // en cours, qui inclura les octets que nous venons de produire. Seule la
    // coroutine qui envoie arme le minuteur ; les autres attendent sans le
    // réarmer (sinon elles s'annuleraient mutuellement).
    while (flushing_) {
        co_await flush_done_.async_wait(use_tuple);
        if (co_await cancelled()) co_return asio::error::operation_aborted;
        if (!socket_.is_open()) co_return asio::error::bad_descriptor;
    }
    flushing_ = true;
    flush_done_.expires_at(asio::steady_timer::time_point::max());
    std::error_code ec;
    for (;;) {
        std::size_t size = 0;
        const void* data = nullptr;
        std::string chunk;
        if (ssl_) {
            if (BIO_ctrl_pending(network_out_) == 0) break;
            const int n = BIO_read(network_out_, write_buffer_.data(), static_cast<int>(write_buffer_.size()));
            if (n <= 0) break;
            data = write_buffer_.data();
            size = static_cast<std::size_t>(n);
        } else {
            if (plain_out_.empty()) break;
            chunk.swap(plain_out_);
            data = chunk.data();
            size = chunk.size();
        }
        auto [wec, written] = co_await asio::async_write(socket_, asio::buffer(data, size), use_tuple);
        (void)written;
        if (wec) {
            ec = wec;
            break;
        }
    }
    flushing_ = false;
    flush_done_.cancel();
    co_return ec;
}

asio::awaitable<std::error_code> Stream::fill() {
    auto [ec, n] = co_await socket_.async_read_some(asio::buffer(read_buffer_), use_tuple);
    if (ec) co_return ec;
    if (BIO_write(network_in_, read_buffer_.data(), static_cast<int>(n)) != static_cast<int>(n)) {
        co_return tls_error();
    }
    co_return std::error_code{};
}

std::error_code Stream::tls_error() {
    const unsigned long code = ERR_peek_last_error();
    ERR_clear_error();
    if (code == 0) return asio::error::connection_aborted;
    return std::error_code(static_cast<int>(code), asio::error::get_ssl_category());
}

}  // namespace tlsrelay::relay
