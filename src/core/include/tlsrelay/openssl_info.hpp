#pragma once

#include <string>

namespace tlsrelay {

// Version de la bibliothèque OpenSSL réellement chargée (liaison dynamique).
std::string openssl_runtime_version();

// Vrai si la version chargée est au moins 3.0 (SPEC §10).
bool openssl_runtime_supported();

}  // namespace tlsrelay
