#pragma once

#include "tlsrelay/tls/context.hpp"

#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace tlsrelay::relay {

// Stream of a channel: plain TCP, or TLS 1.3 over TCP.
//
// TLS is implemented directly on OpenSSL with memory BIOs, which
// allows half-close (close_notify in one direction only, the other direction
// still receiving) and full access to the session.
//
// One read and one write may be in progress at the same time, on the
// same strand; writes to the socket are serialized internally.
class Stream {
public:
    // Plain stream.
    explicit Stream(asio::ip::tcp::socket socket);
    // TLS stream. The role (client or server) is that of the context. server_name
    // is used on the client side for SNI and for certificate verification.
    Stream(asio::ip::tcp::socket socket, std::shared_ptr<const tls::Context> context,
           const std::string& server_name = {});
    ~Stream();

    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    bool is_tls() const { return ssl_ != nullptr; }
    // TLS context (hence PKI generation) of the stream, nullptr when plain.
    const tls::Context* context() const { return context_.get(); }
    asio::ip::tcp::socket& socket() { return socket_; }

    // TLS: establishes the session and verifies the peer. No effect when plain.
    // On failure, failure_reason() gives the details.
    asio::awaitable<std::error_code> handshake();

    // Returns asio::error::eof at the clean end of the stream (close_notify with TLS).
    asio::awaitable<std::pair<std::error_code, std::size_t>> read_some(asio::mutable_buffer buffer);
    // Writes and sends. Writes never interleave, even concurrent ones.
    asio::awaitable<std::error_code> write(asio::const_buffer buffer);

    // Adds to the send buffer without waiting; flush() sends. Allows sending a
    // last frame just before closing.
    std::error_code queue(asio::const_buffer buffer);
    asio::awaitable<std::error_code> flush();

    // TLS 1.3 key exporter (RFC 8446 §7.5). False when plain or on failure.
    bool export_keying_material(std::string_view label, const std::uint8_t* context, std::size_t context_size,
                                std::uint8_t* out, std::size_t out_size) const;

    // End of this send direction; reception continues.
    asio::awaitable<std::error_code> shutdown_send();

    void close();

    // After handshake: "TLSv1.3 TLS_AES_256_GCM_SHA384", and subject of the peer certificate.
    std::string session_description() const;
    std::string peer_subject() const;
    // Certificate presented by the peer (nullptr when plain or if it presented none).
    X509* peer_certificate() const;
    const std::string& failure_reason() const { return failure_reason_; }
    // The handshake failed because the connection was lost (and not refused).
    bool handshake_interrupted() const { return handshake_interrupted_; }

private:
    asio::awaitable<std::error_code> fill();
    std::error_code tls_error();

    asio::ip::tcp::socket socket_;
    std::shared_ptr<const tls::Context> context_;  // keeps the generation alive
    tls::SslPtr ssl_;
    BIO* network_in_ = nullptr;   // bytes received from the network, read by OpenSSL (owned by ssl_)
    BIO* network_out_ = nullptr;  // bytes produced by OpenSSL, to be sent (owned by ssl_)
    std::vector<unsigned char> read_buffer_;
    std::vector<unsigned char> write_buffer_;
    std::string plain_out_;  // plain: bytes waiting to be sent
    bool flushing_ = false;
    asio::steady_timer flush_done_;
    std::string failure_reason_;
    bool handshake_interrupted_ = false;
};

}  // namespace tlsrelay::relay
