#pragma once

#include <string_view>

namespace tlsrelay::system {

// Notification to the systemd service manager (Type=notify): READY=1,
// STOPPING=1, STATUS=... No effect outside systemd (NOTIFY_SOCKET absent) and
// on Windows. Direct implementation of the protocol, without libsystemd.
void notify(std::string_view state);

}  // namespace tlsrelay::system
