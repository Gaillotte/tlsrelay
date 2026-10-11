#pragma once

#include "tlsrelay/tls/context.hpp"

#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace tlsrelay::relay {

// Flux d'un canal : TCP en clair, ou TLS 1.3 sur TCP.
//
// Le TLS est implémenté directement sur OpenSSL avec des BIO mémoire, ce qui
// permet la demi-fermeture (close_notify dans un seul sens, l'autre sens
// continuant à recevoir) et l'accès complet à la session.
//
// Une lecture et une écriture peuvent être en cours en même temps, sur le
// même strand ; les écritures sur la socket sont sérialisées en interne.
class Stream {
public:
    // Flux en clair.
    explicit Stream(asio::ip::tcp::socket socket);
    // Flux TLS. Le rôle (client ou serveur) est celui du contexte. server_name
    // sert côté client au SNI et à la vérification du certificat.
    Stream(asio::ip::tcp::socket socket, std::shared_ptr<const tls::Context> context,
           const std::string& server_name = {});
    ~Stream();

    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    bool is_tls() const { return ssl_ != nullptr; }
    asio::ip::tcp::socket& socket() { return socket_; }

    // TLS : établit la session et vérifie le pair. Sans effet en clair.
    // En cas d'échec, failure_reason() donne le détail.
    asio::awaitable<std::error_code> handshake();

    // Retourne asio::error::eof à la fin propre du flux (close_notify en TLS).
    asio::awaitable<std::pair<std::error_code, std::size_t>> read_some(asio::mutable_buffer buffer);
    asio::awaitable<std::error_code> write(asio::const_buffer buffer);

    // Fin de ce sens d'émission ; la réception continue.
    asio::awaitable<std::error_code> shutdown_send();

    void close();

    // Après handshake : « TLSv1.3 TLS_AES_256_GCM_SHA384 », et sujet du certificat du pair.
    std::string session_description() const;
    std::string peer_subject() const;
    // Certificat présenté par le pair (nullptr en clair ou s'il n'en a pas présenté).
    X509* peer_certificate() const;
    const std::string& failure_reason() const { return failure_reason_; }

private:
    asio::awaitable<std::error_code> flush();
    asio::awaitable<std::error_code> fill();
    std::error_code tls_error();

    asio::ip::tcp::socket socket_;
    std::shared_ptr<const tls::Context> context_;  // maintient la génération en vie
    tls::SslPtr ssl_;
    BIO* network_in_ = nullptr;   // octets reçus du réseau, lus par OpenSSL (appartient à ssl_)
    BIO* network_out_ = nullptr;  // octets produits par OpenSSL, à envoyer (appartient à ssl_)
    std::vector<unsigned char> read_buffer_;
    std::vector<unsigned char> write_buffer_;
    bool flushing_ = false;
    asio::steady_timer flush_done_;
    std::string failure_reason_;
};

}  // namespace tlsrelay::relay
