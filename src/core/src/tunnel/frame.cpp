#include "tlsrelay/tunnel/frame.hpp"

#include <algorithm>
#include <cstring>

namespace tlsrelay::tunnel {
namespace {

void put_u16(std::string& out, std::uint16_t v) {
    out += static_cast<char>(v >> 8);
    out += static_cast<char>(v & 0xff);
}

void put_u32(std::string& out, std::uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) out += static_cast<char>((v >> shift) & 0xff);
}

void put_u64(std::string& out, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) out += static_cast<char>((v >> shift) & 0xff);
}

std::uint16_t get_u16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }

std::uint32_t get_u32(const std::uint8_t* p) {
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | p[3];
}

std::uint64_t get_u64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

std::string frame(FrameType type, std::string_view payload) {
    std::string out;
    out.reserve(kHeaderSize + payload.size());
    out += static_cast<char>(type);
    out += '\0';  // flags
    put_u16(out, 0);  // réservé
    put_u32(out, static_cast<std::uint32_t>(payload.size()));
    out.append(payload.data(), payload.size());
    return out;
}

std::string u64_payload(std::uint64_t v) {
    std::string p;
    put_u64(p, v);
    return p;
}

std::string status_payload(std::uint16_t code, std::string_view message) {
    std::string p;
    put_u16(p, code);
    p.append(message.substr(0, kMaxMessage));
    return p;
}

// Taille de charge utile acceptée pour chaque type.
bool valid_size(FrameType type, std::size_t size) {
    switch (type) {
        case FrameType::open: return size == 2 + 16 + 1;
        case FrameType::open_ok: return size == 0;
        case FrameType::open_fail:
        case FrameType::close: return size >= 2 && size <= 2 + kMaxMessage;
        case FrameType::data: return size > 8 && size <= 8 + kMaxData;
        case FrameType::ack:
        case FrameType::shutdown_wr:
        case FrameType::resumed:
        case FrameType::ping:
        case FrameType::pong: return size == 8;
        case FrameType::resume: return size == 16 + 32 + 8;
        case FrameType::resume_fail: return size == 2;
    }
    return false;
}

bool known_type(std::uint8_t t) {
    switch (static_cast<FrameType>(t)) {
        case FrameType::open:
        case FrameType::open_ok:
        case FrameType::open_fail:
        case FrameType::data:
        case FrameType::ack:
        case FrameType::shutdown_wr:
        case FrameType::close:
        case FrameType::resume:
        case FrameType::resumed:
        case FrameType::resume_fail:
        case FrameType::ping:
        case FrameType::pong: return true;
    }
    return false;
}

}  // namespace

std::string_view to_string(FrameType type) {
    switch (type) {
        case FrameType::open: return "OPEN";
        case FrameType::open_ok: return "OPEN_OK";
        case FrameType::open_fail: return "OPEN_FAIL";
        case FrameType::data: return "DATA";
        case FrameType::ack: return "ACK";
        case FrameType::shutdown_wr: return "SHUTDOWN_WR";
        case FrameType::close: return "CLOSE";
        case FrameType::resume: return "RESUME";
        case FrameType::resumed: return "RESUMED";
        case FrameType::resume_fail: return "RESUME_FAIL";
        case FrameType::ping: return "PING";
        case FrameType::pong: return "PONG";
    }
    return "?";
}

std::string_view to_string(CloseCode code) {
    switch (code) {
        case CloseCode::normal: return "NORMAL";
        case CloseCode::idle_timeout: return "IDLE_TIMEOUT";
        case CloseCode::lifetime_exceeded: return "LIFETIME_EXCEEDED";
        case CloseCode::peer_revoked: return "PEER_REVOKED";
        case CloseCode::dest_unreachable: return "DEST_UNREACHABLE";
        case CloseCode::shutdown: return "SHUTDOWN";
        case CloseCode::protocol_error: return "PROTOCOL_ERROR";
        case CloseCode::frame_too_large: return "FRAME_TOO_LARGE";
        case CloseCode::buffer_overflow: return "BUFFER_OVERFLOW";
        case CloseCode::not_authorized: return "NOT_AUTHORIZED";
        case CloseCode::internal_error: return "INTERNAL_ERROR";
    }
    return "?";
}

std::string to_hex(const std::uint8_t* data, std::size_t size) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0xf];
    }
    return out;
}

std::string encode_open(const Open& open) {
    std::string p;
    put_u16(p, open.version);
    p.append(reinterpret_cast<const char*>(open.session.data()), open.session.size());
    p += static_cast<char>(open.port == PortKind::plain ? 1 : open.port == PortKind::tls ? 2 : 3);
    return frame(FrameType::open, p);
}

std::string encode_open_ok() { return frame(FrameType::open_ok, {}); }

std::string encode_open_fail(std::uint16_t code, std::string_view message) {
    return frame(FrameType::open_fail, status_payload(code, message));
}

std::string encode_data(std::uint64_t seq, const void* bytes, std::size_t size) {
    std::string out;
    out.reserve(kHeaderSize + 8 + size);
    out += static_cast<char>(FrameType::data);
    out += '\0';
    put_u16(out, 0);
    put_u32(out, static_cast<std::uint32_t>(8 + size));
    put_u64(out, seq);
    out.append(static_cast<const char*>(bytes), size);
    return out;
}

std::string encode_ack(std::uint64_t seq) { return frame(FrameType::ack, u64_payload(seq)); }
std::string encode_shutdown_wr(std::uint64_t final_seq) { return frame(FrameType::shutdown_wr, u64_payload(final_seq)); }

std::string encode_close(std::uint16_t code, std::string_view message) {
    return frame(FrameType::close, status_payload(code, message));
}

std::string encode_resume(const Resume& resume) {
    std::string p;
    p.append(reinterpret_cast<const char*>(resume.session.data()), resume.session.size());
    p.append(reinterpret_cast<const char*>(resume.token.data()), resume.token.size());
    put_u64(p, resume.last_rx_seq);
    return frame(FrameType::resume, p);
}

std::string encode_resumed(std::uint64_t last_rx_seq) { return frame(FrameType::resumed, u64_payload(last_rx_seq)); }

std::string encode_resume_fail(std::uint16_t code) {
    std::string p;
    put_u16(p, code);
    return frame(FrameType::resume_fail, p);
}

std::string encode_ping(std::uint64_t nonce) { return frame(FrameType::ping, u64_payload(nonce)); }
std::string encode_pong(std::uint64_t nonce) { return frame(FrameType::pong, u64_payload(nonce)); }

Open read_open(const Frame& f) {
    Open o;
    o.version = get_u16(f.payload.data());
    std::copy_n(f.payload.data() + 2, o.session.size(), o.session.begin());
    const auto kind = f.payload[18];
    o.port = kind == 2 ? PortKind::tls : kind == 3 ? PortKind::mtls : PortKind::plain;
    return o;
}

Data read_data(const Frame& f) {
    return {get_u64(f.payload.data()), f.payload.data() + 8, f.payload.size() - 8};
}

std::uint64_t read_u64(const Frame& f) { return get_u64(f.payload.data()); }

Status read_status(const Frame& f) {
    Status s;
    s.code = get_u16(f.payload.data());
    static const char* digits = "0123456789abcdef";
    for (std::size_t i = 2; i < f.payload.size(); ++i) {
        const auto c = f.payload[i];
        if (c < 0x20 || c == 0x7f || c == '\\') {
            s.message += '\\';
            s.message += 'x';
            s.message += digits[c >> 4];
            s.message += digits[c & 0xf];
        } else {
            s.message += static_cast<char>(c);
        }
    }
    return s;
}

Resume read_resume(const Frame& f) {
    Resume r;
    std::copy_n(f.payload.data(), r.session.size(), r.session.begin());
    std::copy_n(f.payload.data() + 16, r.token.size(), r.token.begin());
    r.last_rx_seq = get_u64(f.payload.data() + 48);
    return r;
}

std::uint16_t read_code(const Frame& f) { return get_u16(f.payload.data()); }

void Decoder::feed(const std::uint8_t* data, std::size_t size) {
    if (error_ != Error::none) return;
    // Compactage : on ne garde que les octets non encore consommés.
    if (offset_ > 0 && offset_ == buffer_.size()) {
        buffer_.clear();
        offset_ = 0;
    } else if (offset_ > 64ULL * 1024) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(offset_));
        offset_ = 0;
    }
    buffer_.insert(buffer_.end(), data, data + size);
}

std::optional<Frame> Decoder::next() {
    if (error_ != Error::none) return std::nullopt;
    const std::size_t available = buffer_.size() - offset_;
    if (available < kHeaderSize) return std::nullopt;
    const std::uint8_t* h = buffer_.data() + offset_;

    if (!known_type(h[0])) {
        error_ = Error::protocol_error;
        detail_ = "type de trame inconnu 0x" + to_hex(h, 1);
        return std::nullopt;
    }
    if (h[2] != 0 || h[3] != 0) {
        error_ = Error::protocol_error;
        detail_ = "champ réservé non nul";
        return std::nullopt;
    }
    const auto type = static_cast<FrameType>(h[0]);
    const std::uint32_t length = get_u32(h + 4);
    if (length > kMaxPayload) {
        error_ = Error::frame_too_large;
        detail_ = "trame de " + std::to_string(length) + " octets";
        return std::nullopt;
    }
    if (!valid_size(type, length)) {
        error_ = Error::protocol_error;
        detail_ = "taille " + std::to_string(length) + " invalide pour " + std::string(to_string(type));
        return std::nullopt;
    }
    if (available < kHeaderSize + length) return std::nullopt;
    if (type == FrameType::open && (h[kHeaderSize + 18] < 1 || h[kHeaderSize + 18] > 3)) {
        error_ = Error::protocol_error;
        detail_ = "type de port inconnu dans OPEN";
        return std::nullopt;
    }

    Frame f;
    f.type = type;
    f.payload.assign(h + kHeaderSize, h + kHeaderSize + length);
    offset_ += kHeaderSize + length;
    return f;
}

}  // namespace tlsrelay::tunnel
