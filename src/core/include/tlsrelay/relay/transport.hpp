#pragma once

#include "tlsrelay/relay/stream.hpp"
#include "tlsrelay/tunnel/frame.hpp"
#include "tlsrelay/units.hpp"

#include <asio/awaitable.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace tlsrelay::relay {

// Connexion de transport entre deux tlsrelay : un flux (clair ou TLS) et le
// décodeur de trames, qui peut contenir des octets reçus mais pas encore lus.
struct Transport {
    explicit Transport(std::shared_ptr<Stream> s) : stream(std::move(s)), buffer(16 * 1024) {}

    std::shared_ptr<Stream> stream;
    tunnel::Decoder decoder;
    std::vector<std::uint8_t> buffer;
    bool broken = false;  // erreur constatée : plus aucune écriture
};

struct FrameRead {
    std::optional<tunnel::Frame> frame;
    std::error_code error;                                   // erreur réseau
    tunnel::Decoder::Error protocol = tunnel::Decoder::Error::none;  // trame non conforme
};

// Lit la prochaine trame complète.
asio::awaitable<FrameRead> read_frame(Transport& transport);

// Idem, avec délai : error vaut asio::error::timed_out à l'échéance (la
// connexion est alors fermée).
asio::awaitable<FrameRead> read_frame(Transport& transport, Duration timeout);

// Handshake TLS avec délai (la connexion est fermée à l'échéance). Retourne le
// motif d'échec, vide en cas de succès.
asio::awaitable<std::string> secure(std::shared_ptr<Stream> stream, Duration timeout);

// Jeton de reprise de la connexion n d'une session (SPEC §4.5).
std::optional<tunnel::Token> derive_token(const Stream& stream, const tunnel::SessionId& session, std::uint32_t n);

}  // namespace tlsrelay::relay
