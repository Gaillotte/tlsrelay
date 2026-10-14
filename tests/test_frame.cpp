// Format des trames du protocole de tunnel (SPEC §4.1, §4.2).

#include "tlsrelay/tunnel/frame.hpp"

#include <gtest/gtest.h>

using namespace tlsrelay;
using namespace tlsrelay::tunnel;

namespace {

std::vector<Frame> decode_all(const std::string& bytes, std::size_t step = 0) {
    Decoder d;
    std::vector<Frame> out;
    if (step == 0) step = bytes.size();
    for (std::size_t i = 0; i < bytes.size(); i += step) {
        d.feed(reinterpret_cast<const std::uint8_t*>(bytes.data()) + i, std::min(step, bytes.size() - i));
        while (auto f = d.next()) out.push_back(std::move(*f));
    }
    EXPECT_EQ(d.error(), Decoder::Error::none) << d.error_detail();
    return out;
}

Decoder::Error decode_error(const std::string& bytes, std::string* detail = nullptr) {
    Decoder d;
    d.feed(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
    while (d.next()) {
    }
    if (detail) *detail = d.error_detail();
    return d.error();
}

std::string header(std::uint8_t type, std::uint32_t length, std::uint16_t reserved = 0) {
    std::string h;
    h += static_cast<char>(type);
    h += '\0';
    h += static_cast<char>(reserved >> 8);
    h += static_cast<char>(reserved & 0xff);
    for (int shift = 24; shift >= 0; shift -= 8) h += static_cast<char>((length >> shift) & 0xff);
    return h;
}

}  // namespace

TEST(Frame, HeaderIsBigEndian) {
    const auto f = encode_ack(0x0102030405060708ULL);
    ASSERT_EQ(f.size(), kHeaderSize + 8);
    EXPECT_EQ(f.substr(0, 8), header(0x11, 8));
    EXPECT_EQ(f.substr(8), std::string("\x01\x02\x03\x04\x05\x06\x07\x08", 8));
}

TEST(Frame, RoundTripOfEveryType) {
    Open open;
    open.port = PortKind::mtls;
    for (std::size_t i = 0; i < open.session.size(); ++i) open.session[i] = static_cast<std::uint8_t>(i + 1);
    Resume resume;
    resume.session = open.session;
    resume.token.fill(0xab);
    resume.last_rx_seq = 123456789;
    const std::string payload = "données utiles";

    const std::string all = encode_open(open) + encode_open_ok() + encode_open_fail(4, "injoignable") +
                            encode_data(7, payload.data(), payload.size()) + encode_ack(7) + encode_shutdown_wr(9) +
                            encode_close(0, "fin") + encode_resume(resume) + encode_resumed(42) +
                            encode_resume_fail(9) + encode_ping(1) + encode_pong(2);

    for (std::size_t step : {std::size_t{0}, std::size_t{1}, std::size_t{5}}) {
        const auto frames = decode_all(all, step);
        ASSERT_EQ(frames.size(), 12u) << "pas=" << step;
        const auto o = read_open(frames[0]);
        EXPECT_EQ(o.version, kVersion);
        EXPECT_EQ(o.session, open.session);
        EXPECT_EQ(o.port, PortKind::mtls);
        EXPECT_EQ(frames[1].type, FrameType::open_ok);
        EXPECT_EQ(read_status(frames[2]).code, 4);
        EXPECT_EQ(read_status(frames[2]).message, "injoignable");
        const auto d = read_data(frames[3]);
        EXPECT_EQ(d.seq, 7u);
        EXPECT_EQ(std::string(reinterpret_cast<const char*>(d.bytes), d.size), payload);
        EXPECT_EQ(read_u64(frames[4]), 7u);
        EXPECT_EQ(read_u64(frames[5]), 9u);
        EXPECT_EQ(read_status(frames[6]).message, "fin");
        const auto r = read_resume(frames[7]);
        EXPECT_EQ(r.session, resume.session);
        EXPECT_EQ(r.token, resume.token);
        EXPECT_EQ(r.last_rx_seq, 123456789u);
        EXPECT_EQ(read_u64(frames[8]), 42u);
        EXPECT_EQ(read_code(frames[9]), 9);
        EXPECT_EQ(frames[10].type, FrameType::ping);
        EXPECT_EQ(frames[11].type, FrameType::pong);
    }
}

TEST(Frame, StatusMessageIsTruncated) {
    const auto f = decode_all(encode_close(6, std::string(1000, 'x')));
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(read_status(f[0]).message.size(), kMaxMessage);
}

TEST(Frame, StatusMessageControlCharactersAreEscaped) {
    // Message venu de l'autre tlsrelay, destiné aux journaux : pas de nouvelle ligne
    // ni de séquence d'échappement de terminal.
    const auto f = decode_all(encode_close(6, "fin\n2026-01-01 info  [config] faux\x1b[31m\\"));
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(read_status(f[0]).message, "fin\\x0a2026-01-01 info  [config] faux\\x1b[31m\\x5c");
}

TEST(Frame, WaitsForCompleteFrame) {
    const auto bytes = encode_ack(1);
    Decoder d;
    d.feed(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size() - 1);
    EXPECT_FALSE(d.next());
    EXPECT_EQ(d.error(), Decoder::Error::none);
    d.feed(reinterpret_cast<const std::uint8_t*>(bytes.data()) + bytes.size() - 1, 1);
    EXPECT_TRUE(d.next());
}

TEST(Frame, RejectsUnknownType) {
    std::string detail;
    EXPECT_EQ(decode_error(header(0x7f, 0), &detail), Decoder::Error::protocol_error);
    EXPECT_NE(detail.find("inconnu"), std::string::npos) << detail;
}

TEST(Frame, RejectsNonZeroReservedField) {
    EXPECT_EQ(decode_error(header(0x02, 0, 1)), Decoder::Error::protocol_error);
}

TEST(Frame, RejectsOversizedFrameFromHeaderAlone) {
    // L'erreur est détectée dès l'en-tête, sans attendre (ni stocker) la charge utile.
    EXPECT_EQ(decode_error(header(0x10, kMaxPayload + 1)), Decoder::Error::frame_too_large);
}

TEST(Frame, RejectsSizeInconsistentWithType) {
    EXPECT_EQ(decode_error(header(0x02, 1) + "x"), Decoder::Error::protocol_error);              // OPEN_OK non vide
    EXPECT_EQ(decode_error(header(0x11, 4) + "abcd"), Decoder::Error::protocol_error);           // ACK court
    EXPECT_EQ(decode_error(header(0x10, 8) + std::string(8, '\0')), Decoder::Error::protocol_error);  // DATA vide
    EXPECT_EQ(decode_error(header(0x10, 8 + kMaxData + 1) + std::string(8 + kMaxData + 1, 'x')),
              Decoder::Error::protocol_error);
}

TEST(Frame, RejectsUnknownPortKindInOpen) {
    std::string payload(19, '\0');
    payload[1] = 1;   // version
    payload[18] = 4;  // type de port inconnu
    EXPECT_EQ(decode_error(header(0x01, 19) + payload), Decoder::Error::protocol_error);
}

TEST(Frame, ErrorIsFinal) {
    Decoder d;
    const auto bad = header(0x7f, 0);
    d.feed(reinterpret_cast<const std::uint8_t*>(bad.data()), bad.size());
    EXPECT_FALSE(d.next());
    const auto good = encode_ack(1);
    d.feed(reinterpret_cast<const std::uint8_t*>(good.data()), good.size());
    EXPECT_FALSE(d.next());
    EXPECT_EQ(d.error(), Decoder::Error::protocol_error);
}

// Noms journalisés des trames et des codes de fermeture (SPEC §4.2, §4.6).
TEST(Frame, NamesOfEveryTypeAndCode) {
    const std::vector<std::pair<FrameType, std::string_view>> types = {
        {FrameType::open, "OPEN"},         {FrameType::open_ok, "OPEN_OK"},
        {FrameType::open_fail, "OPEN_FAIL"}, {FrameType::data, "DATA"},
        {FrameType::ack, "ACK"},           {FrameType::shutdown_wr, "SHUTDOWN_WR"},
        {FrameType::close, "CLOSE"},       {FrameType::resume, "RESUME"},
        {FrameType::resumed, "RESUMED"},   {FrameType::resume_fail, "RESUME_FAIL"},
        {FrameType::ping, "PING"},         {FrameType::pong, "PONG"}};
    for (const auto& [type, name] : types) EXPECT_EQ(to_string(type), name);
    EXPECT_EQ(to_string(static_cast<FrameType>(0x7f)), "?");

    const std::vector<std::pair<CloseCode, std::string_view>> codes = {
        {CloseCode::normal, "NORMAL"},
        {CloseCode::idle_timeout, "IDLE_TIMEOUT"},
        {CloseCode::lifetime_exceeded, "LIFETIME_EXCEEDED"},
        {CloseCode::peer_revoked, "PEER_REVOKED"},
        {CloseCode::dest_unreachable, "DEST_UNREACHABLE"},
        {CloseCode::shutdown, "SHUTDOWN"},
        {CloseCode::protocol_error, "PROTOCOL_ERROR"},
        {CloseCode::frame_too_large, "FRAME_TOO_LARGE"},
        {CloseCode::buffer_overflow, "BUFFER_OVERFLOW"},
        {CloseCode::not_authorized, "NOT_AUTHORIZED"},
        {CloseCode::internal_error, "INTERNAL_ERROR"}};
    for (const auto& [code, name] : codes) EXPECT_EQ(to_string(code), name);
    EXPECT_EQ(to_string(static_cast<CloseCode>(999)), "?");
}

// Chaque type refuse toute taille autre que la sienne (SPEC §4.2).
TEST(Frame, RejectsWrongSizeForEachType) {
    const std::vector<std::pair<std::uint8_t, std::uint32_t>> wrong = {
        {0x01, 18}, {0x01, 20},          // OPEN : 19
        {0x02, 1},                       // OPEN_OK : vide
        {0x03, 1},  {0x03, 2 + 257},     // OPEN_FAIL : 2 à 258
        {0x10, 8},                       // DATA : au moins un octet de données
        {0x11, 7},  {0x12, 9},  {0x13, 1}, {0x20, 55},
        {0x21, 0},  {0x22, 3},  {0x30, 4}, {0x31, 16}};
    for (const auto& [type, size] : wrong) {
        std::string detail;
        EXPECT_EQ(decode_error(header(type, size) + std::string(size, '\0'), &detail), Decoder::Error::protocol_error)
            << "type 0x" << std::hex << int(type) << " taille " << std::dec << size;
        EXPECT_NE(detail.find("invalide pour"), std::string::npos) << detail;
    }
    // Type de port hors de 1..3 dans OPEN.
    for (const std::uint8_t kind : {std::uint8_t{0}, std::uint8_t{4}}) {
        std::string open = header(0x01, 19) + std::string("\x00\x01", 2) + std::string(16, 'x');
        open += static_cast<char>(kind);
        EXPECT_EQ(decode_error(open), Decoder::Error::protocol_error) << int(kind);
    }
}

// Plus de 64 Kio consommés : le tampon interne est compacté sans perdre de trame.
TEST(Frame, DecoderCompactsLargeBuffers) {
    std::string stream;
    std::vector<std::string> payloads;
    for (int i = 0; i < 40; ++i) {
        payloads.emplace_back(4000 + static_cast<std::size_t>(i), static_cast<char>('a' + i % 26));
        stream += encode_data(static_cast<std::uint64_t>(i + 1), payloads.back().data(), payloads.back().size());
    }
    // Morceaux de taille impaire : la plupart des appels laissent une trame incomplète.
    const auto frames = decode_all(stream, 1531);
    ASSERT_EQ(frames.size(), payloads.size());
    for (std::size_t i = 0; i < frames.size(); ++i) {
        const auto data = read_data(frames[i]);
        EXPECT_EQ(data.seq, i + 1);
        EXPECT_EQ(std::string(reinterpret_cast<const char*>(data.bytes), data.size), payloads[i]);
    }
}
