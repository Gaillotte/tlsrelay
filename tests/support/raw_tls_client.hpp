#pragma once

// Client TLS « brut » (OpenSSL bloquant) pour simuler des pairs non conformes.

#include "support/net_helpers.hpp"
#include "support/test_pki.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <csignal>
#include <optional>
#include <string>

namespace testnet {

// Client TLS « brut » (OpenSSL bloquant) pour simuler des pairs non conformes.
class RawTlsClient {
public:
    // identity : certificat présenté au serveur (mTLS), avec sa clé et sa chaîne.
    RawTlsClient(std::uint16_t port, int max_version, std::optional<std::string> alpn, const X509* root = nullptr,
                 const testpki::Issued* identity = nullptr, const X509* chain = nullptr)
        : socket_(io_) {
#ifndef _WIN32
        std::signal(SIGPIPE, SIG_IGN);
#endif
        socket_.connect(tcp::endpoint(loopback(), port));
        ctx_.reset(SSL_CTX_new(TLS_client_method()));
        SSL_CTX_set_max_proto_version(ctx_.get(), max_version);
        if (root) {
            X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx_.get()), const_cast<X509*>(root));
            SSL_CTX_set_verify(ctx_.get(), SSL_VERIFY_PEER, nullptr);
        }
        if (alpn) {
            const std::string wire = std::string(1, static_cast<char>(alpn->size())) + *alpn;
            SSL_CTX_set_alpn_protos(ctx_.get(), reinterpret_cast<const unsigned char*>(wire.data()),
                                    static_cast<unsigned>(wire.size()));
        }
        if (identity) {
            SSL_CTX_use_certificate(ctx_.get(), identity->cert.get());
            SSL_CTX_use_PrivateKey(ctx_.get(), identity->key.get());
            if (chain) SSL_CTX_add1_chain_cert(ctx_.get(), const_cast<X509*>(chain));
        }
        ssl_.reset(SSL_new(ctx_.get()));
        SSL_set_fd(ssl_.get(), static_cast<int>(socket_.native_handle()));
    }

    bool handshake() {
        ERR_clear_error();
        return SSL_connect(ssl_.get()) == 1;
    }

    // Lecture bloquante : retourne vide si le serveur ferme la connexion.
    std::string read(std::size_t n) {
        std::string out(n, '\0');
        std::size_t got = 0;
        while (got < n) {
            std::size_t r = 0;
            if (SSL_read_ex(ssl_.get(), out.data() + got, n - got, &r) != 1) break;
            got += r;
        }
        out.resize(got);
        return out;
    }

    bool write(const std::string& data) {
        std::size_t w = 0;
        return SSL_write_ex(ssl_.get(), data.data(), data.size(), &w) == 1;
    }

    SSL* ssl() { return ssl_.get(); }

private:
    asio::io_context io_;
    tcp::socket socket_;
    tlsrelay::tls::SslCtxPtr ctx_;
    tlsrelay::tls::SslPtr ssl_;
};

}  // namespace testnet
