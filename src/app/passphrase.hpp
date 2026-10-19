#pragma once

#include <optional>
#include <string>

namespace tlsrelay::app {

// CA passphrase: file (first line), otherwise the TLSRELAY_CA_PASSPHRASE
// variable, otherwise typed on the keyboard without echo (confirm: entered
// twice). std::nullopt if the entry fails or does not match (message printed).
std::optional<std::string> read_passphrase(const std::string& file, bool confirm);

}  // namespace tlsrelay::app
