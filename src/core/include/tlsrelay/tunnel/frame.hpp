#pragma once

// tlsrelay/1 tunnel protocol (SPEC §4): binary frame format.
// All integers are in network order (big-endian).
//
//   0       1       2       3       4                               8
//   +-------+-------+-------+-------+-------------------------------+
//   | type  | flags |  reserved (0) |       length (u32)            |
//   +-------+-------+-------+-------+-------------------------------+
//   |                  payload (length bytes)                       |

#include "tlsrelay/config.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tlsrelay::tunnel {

inline constexpr std::uint16_t kVersion = 1;
inline constexpr std::size_t kHeaderSize = 8;
inline constexpr std::size_t kMaxData = 16ULL * 1024;          // data per DATA frame
inline constexpr std::size_t kMaxPayload = kMaxData + 64;    // maximum payload
inline constexpr std::size_t kMaxMessage = 256;              // message of OPEN_FAIL and CLOSE frames

enum class FrameType : std::uint8_t {
    open = 0x01,
    open_ok = 0x02,
    open_fail = 0x03,
    data = 0x10,
    ack = 0x11,
    shutdown_wr = 0x12,
    close = 0x13,
    resume = 0x20,
    resumed = 0x21,
    resume_fail = 0x22,
    ping = 0x30,
    pong = 0x31,
};

std::string_view to_string(FrameType type);

// Close codes (SPEC §4.6).
enum class CloseCode : std::uint16_t {
    normal = 0,
    idle_timeout = 1,
    lifetime_exceeded = 2,
    peer_revoked = 3,
    dest_unreachable = 4,
    shutdown = 5,
    protocol_error = 6,
    frame_too_large = 7,
    buffer_overflow = 8,
    not_authorized = 9,
    internal_error = 10,
};

std::string_view to_string(CloseCode code);

using SessionId = std::array<std::uint8_t, 16>;
using Token = std::array<std::uint8_t, 32>;

std::string to_hex(const std::uint8_t* data, std::size_t size);

struct Frame {
    FrameType type{};
    std::vector<std::uint8_t> payload;
};

// Decoded contents. Sizes have already been validated by the decoder.
struct Open {
    std::uint16_t version = kVersion;
    SessionId session{};
    PortKind port = PortKind::plain;
};
struct Data {
    std::uint64_t seq = 0;
    const std::uint8_t* bytes = nullptr;
    std::size_t size = 0;
};
struct Status {  // OPEN_FAIL, CLOSE
    std::uint16_t code = 0;
    std::string message;
};
struct Resume {
    SessionId session{};
    Token token{};
    std::uint64_t last_rx_seq = 0;
};

// Encoding: each function returns the complete frame (header included).
std::string encode_open(const Open& open);
std::string encode_open_ok();
std::string encode_open_fail(std::uint16_t code, std::string_view message);
std::string encode_data(std::uint64_t seq, const void* bytes, std::size_t size);
std::string encode_ack(std::uint64_t seq);
std::string encode_shutdown_wr(std::uint64_t final_seq);
std::string encode_close(std::uint16_t code, std::string_view message);
std::string encode_resume(const Resume& resume);
std::string encode_resumed(std::uint64_t last_rx_seq);
std::string encode_resume_fail(std::uint16_t code);
std::string encode_ping(std::uint64_t nonce);
std::string encode_pong(std::uint64_t nonce);

// Reading of a frame's content (type and size checked by Decoder).
Open read_open(const Frame& f);
Data read_data(const Frame& f);
std::uint64_t read_u64(const Frame& f);  // ACK, SHUTDOWN_WR, RESUMED, PING, PONG
// The message comes from the other tlsrelay and ends up in the logs: its
// control characters are escaped (\xNN), one line cannot become two.
Status read_status(const Frame& f);      // OPEN_FAIL, CLOSE
Resume read_resume(const Frame& f);
std::uint16_t read_code(const Frame& f);  // RESUME_FAIL

// Incremental decoder: it is given the received bytes, it returns the complete
// frames. Any malformed frame (unknown type, non-zero reserved field,
// size inconsistent with the type or too large) is a permanent error.
class Decoder {
public:
    enum class Error { none, protocol_error, frame_too_large };

    void feed(const std::uint8_t* data, std::size_t size);

    // Next complete frame, or std::nullopt if more bytes are needed or on error (see error()).
    std::optional<Frame> next();

    Error error() const { return error_; }
    const std::string& error_detail() const { return detail_; }

private:
    std::vector<std::uint8_t> buffer_;
    std::size_t offset_ = 0;
    Error error_ = Error::none;
    std::string detail_;
};

}  // namespace tlsrelay::tunnel
