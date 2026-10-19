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

// Transport connection between two tlsrelay instances: a stream (plain or TLS) and the
// frame decoder, which may hold bytes received but not yet read.
struct Transport {
    explicit Transport(std::shared_ptr<Stream> s) : stream(std::move(s)), buffer(16ULL * 1024) {}

    std::shared_ptr<Stream> stream;
    tunnel::Decoder decoder;
    std::vector<std::uint8_t> buffer;
    bool broken = false;  // error detected: no more writes
};

struct FrameRead {
    std::optional<tunnel::Frame> frame;
    std::error_code error;                                   // network error
    tunnel::Decoder::Error protocol = tunnel::Decoder::Error::none;  // malformed frame
};

// Reads the next complete frame.
asio::awaitable<FrameRead> read_frame(Transport& transport);

// Same, with a timeout: error is asio::error::timed_out when it expires (the
// connection is then closed).
asio::awaitable<FrameRead> read_frame(Transport& transport, Duration timeout);

// TLS handshake with a timeout (the connection is closed when it expires). Returns the
// failure reason, empty on success.
asio::awaitable<std::string> secure(std::shared_ptr<Stream> stream, Duration timeout);

// Resumption token of connection n of a session (SPEC §4.5).
std::optional<tunnel::Token> derive_token(const Stream& stream, const tunnel::SessionId& session, std::uint32_t n);

}  // namespace tlsrelay::relay
