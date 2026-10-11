#include "tlsrelay/system/notify.hpp"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <string>
#endif

namespace tlsrelay::system {

void notify(std::string_view state) {
#ifdef _WIN32
    (void)state;
#else
    const char* path = std::getenv("NOTIFY_SOCKET");
    if (!path || (path[0] != '/' && path[0] != '@')) return;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const std::size_t length = std::strlen(path);
    if (length >= sizeof addr.sun_path) return;
    std::memcpy(addr.sun_path, path, length);
    if (path[0] == '@') addr.sun_path[0] = '\0';  // espace de noms abstrait
    const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    const auto size = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + length);
    ::sendto(fd, state.data(), state.size(), MSG_NOSIGNAL, reinterpret_cast<sockaddr*>(&addr), size);
    ::close(fd);
#endif
}

}  // namespace tlsrelay::system
