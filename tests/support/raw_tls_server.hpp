#pragma once

// Serveur TLS « brut » (OpenSSL bloquant) pour simuler un faux serveur tlsrelay :
// présente le certificat donné et compte les octets applicatifs reçus.

#include "support/net_helpers.hpp"
#include "support/test_pki.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace testnet {

class RawTlsServer {
public:
    // identity : certificat présenté aux clients, avec sa clé et la chaîne jusqu'à la racine (exclue).
    RawTlsServer(const testpki::Issued& identity, const X509* chain) : acceptor_(io_) {
        acceptor_.open(tcp::v4());
        acceptor_.bind(tcp::endpoint(loopback(), 0));
        acceptor_.listen();
        port_ = acceptor_.local_endpoint().port();
        ctx_.reset(SSL_CTX_new(TLS_server_method()));
        SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_3_VERSION);
        SSL_CTX_use_certificate(ctx_.get(), identity.cert.get());
        SSL_CTX_use_PrivateKey(ctx_.get(), identity.key.get());
        if (chain) SSL_CTX_add1_chain_cert(ctx_.get(), const_cast<X509*>(chain));
        SSL_CTX_set_alpn_select_cb(ctx_.get(), &RawTlsServer::select_alpn, nullptr);
        thread_ = std::thread([this] { serve(); });
    }

    ~RawTlsServer() {
        stopping_ = true;
        // Débloque accept() s'il attend encore.
        std::error_code ignored;
        asio::io_context io;
        tcp::socket poke(io);
        poke.connect(tcp::endpoint(loopback(), port()), ignored);
        thread_.join();
    }

    RawTlsServer(const RawTlsServer&) = delete;
    RawTlsServer& operator=(const RawTlsServer&) = delete;

    std::uint16_t port() const { return port_; }
    int handshakes() const { return handshakes_.load(); }        // handshakes TLS aboutis côté serveur
    std::size_t received() const { return received_.load(); }     // octets applicatifs reçus

    // Octets applicatifs reçus (concaténés), à lire une fois les clients fermés.
    std::string data() const {
        std::lock_guard lock(mutex_);
        return data_;
    }

private:
    static int select_alpn(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
                           unsigned int inlen, void*) {
        static const unsigned char kAlpn[] = {10, 't', 'l', 's', 'r', 'e', 'l', 'a', 'y', '/', '1'};
        unsigned char* selected = nullptr;
        if (SSL_select_next_proto(&selected, outlen, kAlpn, sizeof kAlpn, in, inlen) != OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        *out = selected;
        return SSL_TLSEXT_ERR_OK;
    }

    void serve() {
        while (!stopping_) {
            std::error_code ec;
            tcp::socket s(io_);
            acceptor_.accept(s, ec);
            if (ec || stopping_) return;
            tlsrelay::tls::SslPtr ssl(SSL_new(ctx_.get()));
            SSL_set_fd(ssl.get(), static_cast<int>(s.native_handle()));
            ERR_clear_error();
            if (SSL_accept(ssl.get()) != 1) continue;
            ++handshakes_;
            char buffer[4096];
            std::size_t n = 0;
            while (SSL_read_ex(ssl.get(), buffer, sizeof buffer, &n) == 1) {
                std::lock_guard lock(mutex_);
                data_.append(buffer, n);
                received_ += n;
            }
        }
    }

    asio::io_context io_;
    tcp::acceptor acceptor_;
    std::uint16_t port_ = 0;
    tlsrelay::tls::SslCtxPtr ctx_;
    std::atomic<bool> stopping_{false};
    std::atomic<int> handshakes_{0};
    std::atomic<std::size_t> received_{0};
    mutable std::mutex mutex_;
    std::string data_;
    std::thread thread_;
};

}  // namespace testnet
