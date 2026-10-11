// Noms distinctifs de la liste blanche (RFC 4514) et noms alternatifs (--san).
#include "tlsrelay/pki/request.hpp"
#include "tlsrelay/tls/openssl_ptr.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string text(reinterpret_cast<const char*>(data), size);
    std::string error;
    if (auto name = tlsrelay::tls::parse_dn(text, error)) (void)tlsrelay::tls::name_to_string(name.get());
    if (auto sans = tlsrelay::pki::parse_sans({text}, error)) (void)sans->to_openssl();
    return 0;
}
