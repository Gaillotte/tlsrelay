#include "tlsrelay/relay/transport.hpp"

#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

namespace tlsrelay::relay {
namespace {

constexpr std::string_view kTokenLabel = "EXPORTER-tlsrelay-resume";

// Ferme le flux à l'échéance : l'opération en cours se termine alors en
// erreur, sans dépendre de l'annulation par opération (portable).
class Deadline {
public:
    // Le gestionnaire garde expired et le flux en vie : il peut s'exécuter
    // après la fin de l'opération si l'échéance tombe au même moment.
    Deadline(const asio::any_io_executor& ex, const std::shared_ptr<bool>& expired, const std::shared_ptr<Stream>& stream,
             Duration timeout)
        : timer_(ex) {
        timer_.expires_after(timeout);
        timer_.async_wait([expired, stream](std::error_code ec) {
            if (ec) return;  // annulé : l'opération s'est terminée à temps
            *expired = true;
            stream->close();
        });
    }
    ~Deadline() { timer_.cancel(); }

private:
    asio::steady_timer timer_;
};

}  // namespace

asio::awaitable<FrameRead> read_frame(Transport& t) {
    for (;;) {
        if (auto frame = t.decoder.next()) co_return FrameRead{std::move(frame), {}, tunnel::Decoder::Error::none};
        if (t.decoder.error() != tunnel::Decoder::Error::none) {
            co_return FrameRead{std::nullopt, {}, t.decoder.error()};
        }
        auto [ec, n] = co_await t.stream->read_some(asio::buffer(t.buffer));
        if (ec) co_return FrameRead{std::nullopt, ec, tunnel::Decoder::Error::none};
        t.decoder.feed(t.buffer.data(), n);
    }
}

asio::awaitable<FrameRead> read_frame(Transport& t, Duration timeout) {
    auto expired = std::make_shared<bool>(false);
    FrameRead result;
    {
        const auto executor = co_await asio::this_coro::executor;  // hors des arguments (GCC 12)
        Deadline deadline(executor, expired, t.stream, timeout);
        result = co_await read_frame(t);
    }
    if (*expired) result = FrameRead{std::nullopt, asio::error::timed_out, tunnel::Decoder::Error::none};
    co_return result;
}

asio::awaitable<std::string> secure(std::shared_ptr<Stream> stream, Duration timeout) {
    auto expired = std::make_shared<bool>(false);
    std::error_code ec;
    {
        const auto executor = co_await asio::this_coro::executor;  // hors des arguments (GCC 12)
        Deadline deadline(executor, expired, stream, timeout);
        ec = co_await stream->handshake();
    }
    if (*expired) co_return "délai de handshake dépassé (" + format_duration(timeout) + ")";
    if (ec) {
        std::string reason = stream->failure_reason().empty() ? ec.message() : stream->failure_reason();
        co_return reason;
    }
    co_return std::string();
}

std::optional<tunnel::Token> derive_token(const Stream& stream, const tunnel::SessionId& session, std::uint32_t n) {
    std::uint8_t context[20];
    std::copy(session.begin(), session.end(), context);
    for (int i = 0; i < 4; ++i) context[16 + i] = static_cast<std::uint8_t>(n >> (24 - 8 * i));
    tunnel::Token token{};
    if (!stream.export_keying_material(kTokenLabel, context, sizeof context, token.data(), token.size())) {
        return std::nullopt;
    }
    return token;
}

}  // namespace tlsrelay::relay
