// Canal d'administration (SPEC §10.1) : requêtes reçues par le service et
// réponses lues par la ligne de commande.
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
