#pragma once

#include <string_view>

namespace tlsrelay::system {

// Notification au gestionnaire de services systemd (Type=notify) : READY=1,
// STOPPING=1, STATUS=... Sans effet hors systemd (NOTIFY_SOCKET absent) et
// sous Windows. Implémentation directe du protocole, sans libsystemd.
void notify(std::string_view state);

}  // namespace tlsrelay::system
