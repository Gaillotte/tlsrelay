// Seed inputs of the fuzz_frame target, written with the tunnel's own encoder
// so that they always follow the protocol (SPEC §4.1). Run by tools/run-fuzz.sh
// before fuzzing; the repository holds no binary seed file.
// Usage: make_frame_seeds <output directory>
#include "tlsrelay/tunnel/frame.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

using namespace tlsrelay::tunnel;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: make_frame_seeds <output directory>\n";
        return 2;
    }
    const std::filesystem::path dir = argv[1];
    std::filesystem::create_directories(dir);

    Open open;
    std::iota(open.session.begin(), open.session.end(), std::uint8_t{0});
    open.port = tlsrelay::PortKind::tls;
    Resume resume;
    std::iota(resume.token.begin(), resume.token.end(), std::uint8_t{0});
    resume.last_rx_seq = 3;
    const std::string welcome = "welcome";
    const std::string bulk(100, 'x');
    const auto code = [](CloseCode c) { return static_cast<std::uint16_t>(c); };

    const std::vector<std::pair<std::string, std::string>> seeds = {
        {"open", encode_open(open)},
        {"open_ok", encode_open_ok()},
        {"open_fail", encode_open_fail(code(CloseCode::dest_unreachable), "destination unreachable")},
        {"data", encode_data(1, welcome.data(), welcome.size())},
        {"ack_ping", encode_ack(1) + encode_ping(7)},
        {"close", encode_close(code(CloseCode::normal), "end")},
        {"resume", encode_resume(resume)},
        {"mix", encode_data(1, bulk.data(), bulk.size()) + encode_shutdown_wr(1) + encode_resumed(1) +
                    encode_resume_fail(code(CloseCode::not_authorized))},
    };
    for (const auto& [name, frames] : seeds) {
        // First byte: chunk size chosen by fuzz_frame (here 8 bytes per read).
        std::ofstream out(dir / (name + ".seed"), std::ios::binary | std::ios::trunc);
        out << '\x07' << frames;
        if (!out) {
            std::cerr << "cannot write " << (dir / (name + ".seed")).string() << '\n';
            return 1;
        }
    }
    std::cout << seeds.size() << " seed(s) written to " << dir.string() << '\n';
    return 0;
}
