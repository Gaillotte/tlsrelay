// Chargeur de configuration (SPEC §8) : YAML arbitraire.
#include "tlsrelay/config.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto result = tlsrelay::load_config_string(std::string_view(reinterpret_cast<const char*>(data), size));
    (void)result;
    return 0;
}
