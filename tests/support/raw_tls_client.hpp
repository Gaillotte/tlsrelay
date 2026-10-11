#pragma once

// Client TLS « brut » (OpenSSL bloquant) pour simuler des pairs non conformes.

#include "support/net_helpers.hpp"
#include "support/test_pki.hpp"

#include "tlsrelay/tunnel/frame.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <csignal>
#include <optional>
#include <random>
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

    // Lecture bloquante d'au plus n octets : vide si le serveur ferme la connexion.
    std::string read_some(std::size_t n = 16 * 1024) {
        std::string out(n, '\0');
        std::size_t r = 0;
        if (SSL_read_ex(ssl_.get(), out.data(), n, &r) != 1) return {};
        out.resize(r);
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

// Pair tlsrelay minimal au-dessus d'un RawTlsClient : parle le protocole de
// tunnel (SPEC §4) pour vérifier qu'un canal fonctionne de bout en bout.
class TunnelProbe {
public:
    explicit TunnelProbe(RawTlsClient& raw) : raw_(raw) {}

    // OPEN puis attente de OPEN_OK. Retourne la réponse du serveur (OPEN_OK,
    // OPEN_FAIL...) ; session tirée au hasard si elle n'est pas donnée.
    std::optional<tlsrelay::tunnel::Frame> open_frame(tlsrelay::PortKind kind,
                                                      std::optional<tlsrelay::tunnel::SessionId> session = {}) {
        tlsrelay::tunnel::Open o;
        o.port = kind;
        if (session) {
            o.session = *session;
        } else {
            static std::mt19937 engine{std::random_device{}()};
            for (auto& b : o.session) b = static_cast<std::uint8_t>(engine());
        }
        session_ = o.session;
        if (!raw_.write(tlsrelay::tunnel::encode_open(o))) return std::nullopt;
        return next();
    }

    bool open(tlsrelay::PortKind kind, std::optional<tlsrelay::tunnel::SessionId> session = {}) {
        const auto f = open_frame(kind, session);
        return f && f->type == tlsrelay::tunnel::FrameType::open_ok;
    }

    const tlsrelay::tunnel::SessionId& session() const { return session_; }

    bool send(const std::string& data) {
        return raw_.write(tlsrelay::tunnel::encode_data(seq_++, data.data(), data.size()));
    }

    // Fermeture du canal par CLOSE(NORMAL).
    bool close() { return raw_.write(tlsrelay::tunnel::encode_close(0, "fin")); }

    // Données reçues (au plus n octets), jusqu'à la fermeture.
    std::string receive(std::size_t n) {
        while (received_.size() < n) {
            const auto f = next();
            if (!f || f->type == tlsrelay::tunnel::FrameType::close) break;
            if (f->type == tlsrelay::tunnel::FrameType::data) {
                const auto d = tlsrelay::tunnel::read_data(*f);
                received_.append(reinterpret_cast<const char*>(d.bytes), d.size);
            }
        }
        const auto out = received_.substr(0, n);
        received_.erase(0, out.size());
        return out;
    }

    // Vrai quand le canal est fermé (CLOSE reçu ou connexion fermée).
    bool closed() {
        for (;;) {
            const auto f = next();
            if (!f || f->type == tlsrelay::tunnel::FrameType::close) return true;
        }
    }

    // Prochaine trame, ou std::nullopt à la fermeture de la connexion.
    std::optional<tlsrelay::tunnel::Frame> next() {
        for (;;) {
            if (auto f = decoder_.next()) return f;
            if (decoder_.error() != tlsrelay::tunnel::Decoder::Error::none) return std::nullopt;
            const auto chunk = raw_.read_some();
            if (chunk.empty()) return std::nullopt;
            decoder_.feed(reinterpret_cast<const std::uint8_t*>(chunk.data()), chunk.size());
        }
    }

private:
    RawTlsClient& raw_;
    tlsrelay::tunnel::Decoder decoder_;
    std::uint64_t seq_ = 1;
    std::string received_;
    tlsrelay::tunnel::SessionId session_{};
};

}  // namespace testnet
