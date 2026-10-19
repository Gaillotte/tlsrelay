// Administration channel on Linux: Unix socket, flock lock.

#include "tlsrelay/admin/admin.hpp"
#include "tlsrelay/logging.hpp"

#include "session.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/local/stream_protocol.hpp>
#include <asio/post.hpp>
#include <asio/strand.hpp>

#include <fcntl.h>
#include <grp.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <system_error>

namespace tlsrelay::admin {

using local = asio::local::stream_protocol;

namespace {

std::string errno_text() { return std::error_code(errno, std::generic_category()).message(); }

std::string describe_caller(local::socket& socket) {
#ifdef SO_PEERCRED
    ucred cred{};
    socklen_t len = sizeof cred;
    if (getsockopt(socket.native_handle(), SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
        return "uid=" + std::to_string(cred.uid) + " pid=" + std::to_string(cred.pid);
    }
#else
    (void)socket;
#endif
    return "?";
}

}  // namespace

struct Server::Impl : std::enable_shared_from_this<Server::Impl> {
    Impl(asio::io_context& io, std::string ep, Handler& h)
        : endpoint(std::move(ep)), handler(h), acceptor(asio::make_strand(io)) {}

    ~Impl() {
        if (lock_fd >= 0) ::close(lock_fd);
    }

    void open() {
        namespace fs = std::filesystem;
        if (endpoint.size() >= sizeof(sockaddr_un::sun_path)) {
            throw std::runtime_error("administration channel: path too long (" + endpoint + ")");
        }
        const fs::path path(endpoint);
        std::error_code ec;
        if (path.has_parent_path() && !fs::exists(path.parent_path(), ec)) {
            fs::create_directories(path.parent_path(), ec);
            if (ec) {
                throw std::runtime_error("administration channel: cannot create " +
                                         path.parent_path().string() + ": " + ec.message());
            }
            ::chmod(path.parent_path().c_str(), 0750);
        }

        // Instance lock: held during the whole run, released by the system on exit.
        const std::string lock_path = endpoint + ".lock";
        lock_fd = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (lock_fd < 0) {
            throw std::runtime_error("administration channel: cannot open " + lock_path + ": " + errno_text());
        }
        if (::flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
            throw AlreadyRunning("another run of this instance is in progress (lock " + lock_path + ")");
        }

        // Socket of a previous interrupted run: replaced.
        ::unlink(endpoint.c_str());
        try {
            acceptor.open(local());
            acceptor.bind(local::endpoint(endpoint));
            acceptor.listen();
        } catch (const std::system_error& e) {
            throw std::runtime_error("administration channel: cannot listen on " + endpoint + ": " +
                                     e.code().message());
        }
        ::chmod(endpoint.c_str(), 0660);
        if (const group* g = ::getgrnam("tlsrelay")) {
            if (::chown(endpoint.c_str(), static_cast<uid_t>(-1), g->gr_gid) != 0) {
                logging::config().warn("administration channel: tlsrelay group not applied: {}", errno_text());
            }
        }
    }

    asio::awaitable<void> accept_loop() {
        constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);
        for (;;) {
            auto [ec, socket] = co_await acceptor.async_accept(use_tuple);
            if (ec) {
                if (!acceptor.is_open()) co_return;
                continue;
            }
            auto caller = describe_caller(socket);
            auto ex = socket.get_executor();
            asio::co_spawn(ex, detail::serve_session(std::move(socket), handler, std::move(caller)), asio::detached);
        }
    }

    void close() {
        std::error_code ignored;
        if (acceptor.is_open()) {
            acceptor.close(ignored);
            ::unlink(endpoint.c_str());
        }
    }

    std::string endpoint;
    Handler& handler;
    local::acceptor acceptor;
    int lock_fd = -1;
};

Server::Server(asio::io_context& io, std::string endpoint, Handler& handler)
    : impl_(std::make_shared<Impl>(io, std::move(endpoint), handler)) {
    impl_->open();
}

Server::~Server() = default;

void Server::start() {
    asio::co_spawn(impl_->acceptor.get_executor(), [impl = impl_] { return impl->accept_loop(); }, asio::detached);
}

void Server::stop() {
    asio::post(impl_->acceptor.get_executor(), [impl = impl_] { impl->close(); });
}

const std::string& Server::endpoint() const { return impl_->endpoint; }

CallResult call(const std::string& endpoint, const std::string& request, Duration timeout) {
    CallResult result;
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        result.error = errno_text();
        return result;
    }
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (endpoint.size() >= sizeof addr.sun_path) {
        ::close(fd);
        result.error = "path too long: " + endpoint;
        return result;
    }
    std::memcpy(addr.sun_path, endpoint.c_str(), endpoint.size() + 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        const int err = errno;
        result.unreachable = err == ENOENT || err == ECONNREFUSED;
        result.error = result.unreachable ? "instance unreachable (" + endpoint + ")"
                                          : endpoint + ": " + std::error_code(err, std::generic_category()).message();
        ::close(fd);
        return result;
    }

    const std::string line = request + "\n";
    std::size_t sent = 0;
    while (sent < line.size()) {
        const auto n = ::send(fd, line.data() + sent, line.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            result.error = "cannot send: " + errno_text();
            ::close(fd);
            return result;
        }
        sent += static_cast<std::size_t>(n);
    }
    std::string data;
    char buffer[4096];
    for (;;) {
        if (auto reply = detail::decode_reply(data, result.error)) {
            result.reply = std::move(reply);
            break;
        }
        if (!result.error.empty()) break;
        const auto n = ::recv(fd, buffer, sizeof buffer, 0);
        if (n < 0) {
            result.error = errno == EAGAIN || errno == EWOULDBLOCK ? "no reply in time" : errno_text();
            break;
        }
        if (n == 0) {
            result.error = "connection closed before the end of the reply";
            break;
        }
        data.append(buffer, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return result;
}

}  // namespace tlsrelay::admin
