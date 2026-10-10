#include "tlsrelay/openssl_info.hpp"

#include <openssl/crypto.h>

namespace tlsrelay {

std::string openssl_runtime_version() {
    return OpenSSL_version(OPENSSL_VERSION);
}

bool openssl_runtime_supported() {
    return OpenSSL_version_num() >= 0x30000000UL;
}

}  // namespace tlsrelay
