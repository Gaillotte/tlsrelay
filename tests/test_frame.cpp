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
