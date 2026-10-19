// Tunnel frame decoder (SPEC §4.1): arbitrary input, split into
// chunks of variable sizes as on the network.
#include "tlsrelay/tunnel/frame.hpp"

#include <cstddef>
#include <cstdint>

using namespace tlsrelay::tunnel;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) return 0;
    Decoder decoder;
    // The first byte chooses the chunk size (1 to 256 bytes).
    const std::size_t step = static_cast<std::size_t>(data[0]) + 1;
    for (std::size_t offset = 1; offset < size; offset += step) {
        decoder.feed(data + offset, std::min(step, size - offset));
        while (auto f = decoder.next()) {
            switch (f->type) {
                case FrameType::open: (void)read_open(*f); break;
                case FrameType::data: (void)read_data(*f); break;
                case FrameType::open_fail:
                case FrameType::close: (void)read_status(*f); break;
                case FrameType::resume: (void)read_resume(*f); break;
                case FrameType::resume_fail: (void)read_code(*f); break;
                case FrameType::ack:
                case FrameType::shutdown_wr:
                case FrameType::resumed:
                case FrameType::ping:
                case FrameType::pong: (void)read_u64(*f); break;
                case FrameType::open_ok: break;
            }
        }
        if (decoder.error() != Decoder::Error::none) break;
    }
    return 0;
}
