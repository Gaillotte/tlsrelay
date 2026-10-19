#include "tlsrelay/relay/dial.hpp"

#include "tlsrelay/logging.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <string>
#include <variant>

namespace tlsrelay::relay {
namespace {

using asio::ip::tcp;
using namespace asio::experimental::awaitable_operators;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

asio::awaitable<bool> cancelled() {
    auto state = co_await asio::this_coro::cancellation_state;
    co_return state.cancelled() != asio::cancellation_type::none;
}

// One attempt: name resolution, then connection to each address obtained.
asio::awaitable<std::optional<tcp::socket>> attempt(const DialOptions& options, std::error_code& last_error) {
    auto ex = co_await asio::this_coro::executor;

    tcp::resolver resolver(ex);
    auto [rec, results] = co_await resolver.async_resolve(options.target.host, std::to_string(options.target.port), use_tuple);
    if (rec) {
        last_error = rec;
        co_return std::nullopt;
    }

    for (const auto& entry : results) {
        const auto ep = entry.endpoint();
        tcp::socket socket(ex);
        std::error_code ec;
        socket.open(ep.protocol(), ec);
        if (ec) {
            last_error = ec;
            continue;
        }
        if (options.source) {
            if (options.source->is_v4() != ep.address().is_v4()) continue;  // different family
            socket.bind(tcp::endpoint(*options.source, 0), ec);
            if (ec) {
                last_error = ec;
                continue;
            }
        }

        asio::steady_timer timer(ex);
        timer.expires_after(options.timeout);
        auto result = co_await (socket.async_connect(ep, use_tuple) || timer.async_wait(use_tuple));
        if (result.index() == 0) {
            auto [cec] = std::get<0>(result);
            if (!cec) co_return std::optional<tcp::socket>(std::move(socket));
            last_error = cec;
        } else {
            last_error = asio::error::timed_out;
        }
        if (co_await cancelled()) co_return std::nullopt;
    }
    if (!last_error) last_error = asio::error::host_not_found;
    co_return std::nullopt;
}

}  // namespace

asio::awaitable<std::optional<tcp::socket>> dial(DialOptions options, std::uint64_t channel_id, Stats& stats,
                                                 std::error_code* last_error) {
    auto ex = co_await asio::this_coro::executor;
    asio::steady_timer backoff_timer(ex);
    Duration delay = options.backoff;
    const auto target = options.target.to_string();

    for (std::uint32_t n = 1; n <= options.attempts; ++n) {
        if (n > 1) {
            backoff_timer.expires_after(delay);
            co_await backoff_timer.async_wait(use_tuple);
            delay *= 2;
            if (co_await cancelled()) co_return std::nullopt;
        }

        logging::activity().trace("channel={} connection attempt {}/{} to {}", channel_id, n, options.attempts, target);
        std::error_code ec;
        auto socket = co_await attempt(options, ec);
        if (socket) co_return std::move(socket);

        if (last_error) *last_error = ec;
        ++stats.dial_attempt_failures;
        logging::activity().debug("channel={} connection failure {}/{} to {}: {}", channel_id, n, options.attempts,
                                  target, ec.message());
        if (co_await cancelled()) co_return std::nullopt;
    }

    ++stats.dial_failures;
    logging::activity().warn("channel={} {} unreachable after {} attempt(s)", channel_id, target, options.attempts);
    co_return std::nullopt;
}

}  // namespace tlsrelay::relay
