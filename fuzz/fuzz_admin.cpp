// Administration channel (SPEC §10.1): requests received by the service and
// replies read by the command line.
#include "tlsrelay/admin/admin.hpp"

#include "../src/core/src/admin/session.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string text(reinterpret_cast<const char*>(data), size);
    (void)tlsrelay::admin::parse_request(text);
    std::string error;
    (void)tlsrelay::admin::detail::decode_reply(text, error);
    return 0;
}
