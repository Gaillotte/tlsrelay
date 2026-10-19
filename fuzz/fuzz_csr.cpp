// Signing requests received by the mini-CA (SPEC §7.6): arbitrary PEM.
#include "tlsrelay/pki/authority.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    try {
        (void)tlsrelay::pki::inspect_request(std::string(reinterpret_cast<const char*>(data), size));
    } catch (const std::runtime_error&) {
        // refusal expected for almost all inputs
    }
    return 0;
}
