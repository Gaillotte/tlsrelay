// Demandes de signature reçues par la mini-AC (SPEC §7.6) : PEM arbitraire.
#include "tlsrelay/pki/authority.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    try {
        (void)tlsrelay::pki::inspect_request(std::string(reinterpret_cast<const char*>(data), size));
    } catch (const std::runtime_error&) {
        // refus attendu pour presque toutes les entrées
    }
    return 0;
}
