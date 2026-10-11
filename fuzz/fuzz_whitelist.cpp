// Chargeur de liste blanche (SPEC §6) : YAML arbitraire.
#include "tlsrelay/whitelist.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto result =
        tlsrelay::whitelist::Whitelist::load_string(std::string_view(reinterpret_cast<const char*>(data), size));
    (void)result;
    return 0;
}
