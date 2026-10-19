#pragma once

#include <string>

namespace tlsrelay {

// Version of the OpenSSL library actually loaded (dynamic linking).
std::string openssl_runtime_version();

// True if the loaded version is at least 3.0 (SPEC §10).
bool openssl_runtime_supported();

}  // namespace tlsrelay
