#pragma once

// Administration channel (SPEC §10): one command per connection.
//
//   request: one line of text "command arg1 arg2 ...\n" (4 KiB at most)
//   reply: "OK <n>\n" or "ERROR <n>\n", then n bytes of UTF-8 text
//
// Linux: Unix socket (by default /run/tlsrelay/<instance>.sock, mode 0660,
// group tlsrelay if it exists). Windows: named pipe \\.\pipe\tlsrelay-<instance>,
// accessible to Administrators, SYSTEM and the account that runs the instance,
// refused to remote clients. The channel also serves as the instance lock: only
// one run per instance.

#include "tlsrelay/config.hpp"
#include "tlsrelay/units.hpp"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace tlsrelay::admin {

inline constexpr std::size_t kMaxRequest = 4096;

// Default access point of an instance.
std::string default_endpoint(const std::string& instance);
// Access point of a configuration (admin.endpoint, otherwise the default).
std::string endpoint_for(const Config& config);

struct Request {
    std::string command;
    std::vector<std::string> args;
};

// Splits a line into words separated by spaces. std::nullopt if the line
// is empty or contains control characters.
std::optional<Request> parse_request(std::string_view line);

struct Reply {
    bool ok = true;
    std::string body;
};

std::string encode_reply(const Reply& reply);

// Result of a client call: reply absent if the instance is unreachable
// (error gives the reason).
struct CallResult {
    std::optional<Reply> reply;
    std::string error;
    bool unreachable = false;  // no instance is listening on this access point
};

// Blocking client (command line).
CallResult call(const std::string& endpoint, const std::string& request, Duration timeout);

// Handles the received commands. caller describes the caller (uid or pid) for the log.
class Handler {
public:
    virtual ~Handler() = default;
    virtual asio::awaitable<Reply> handle(Request request, std::string caller) = 0;
};

// Another run of the same instance already holds the channel.
class AlreadyRunning : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Server of the channel. The constructor takes the instance lock and opens the
// access point; it throws std::runtime_error if another run of the same
// instance is in progress or if the access point cannot be created.
class Server {
public:
    Server(asio::io_context& io, std::string endpoint, Handler& handler);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    void start();
    // Closes the access point (commands in progress finish). Usable from any thread.
    void stop();

    const std::string& endpoint() const;

    struct Impl;

private:
    std::shared_ptr<Impl> impl_;
};

}  // namespace tlsrelay::admin
