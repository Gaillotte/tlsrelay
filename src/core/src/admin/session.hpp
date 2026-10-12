#pragma once

// Traitement d'une connexion du canal d'administration, commun au socket Unix
// et au named pipe.

#include "tlsrelay/admin/admin.hpp"

#include <asio/as_tuple.hpp>
#include <asio/read_until.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <chrono>
#include <string>

namespace tlsrelay::admin::detail {

inline constexpr auto kRequestTimeout = std::chrono::seconds(5);

// Ferme le flux à l'échéance (lecture ou écriture bloquée par un client lent).
template <class Stream>
void arm(asio::steady_timer& timer, Stream& stream, std::chrono::steady_clock::duration delay) {
    timer.expires_after(delay);
    timer.async_wait([&stream](std::error_code ec) {
        if (ec) return;  // annulé : le flux peut ne plus exister
        std::error_code ignored;
        stream.close(ignored);
    });
}

// Paramètres par valeur : ils doivent vivre dans le cadre de la coroutine.
template <class Stream>
// cppcheck-suppress passedByValue
asio::awaitable<void> serve_session(Stream stream, Handler& handler, std::string caller) {
    constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);
    asio::steady_timer timer(co_await asio::this_coro::executor);

    arm(timer, stream, kRequestTimeout);
    std::string request;
    auto [rec, n] = co_await asio::async_read_until(stream, asio::dynamic_buffer(request, kMaxRequest), '\n', use_tuple);
    timer.cancel();
    if (rec && rec != asio::error::not_found) co_return;  // client parti ou délai dépassé
    // Variables hors des conditions : GCC 12 gère mal une variable déclarée dans
    // la condition d'un if dont le bloc contient un co_await.
    std::optional<Request> parsed;
    if (!rec) parsed = parse_request(std::string_view(request).substr(0, n));
    Reply reply;
    if (rec == asio::error::not_found) {
        reply = {false, "requête trop longue\n"};
    } else if (parsed) {
        reply = co_await handler.handle(std::move(*parsed), caller);
    } else {
        reply = {false, "requête invalide\n"};
    }

    arm(timer, stream, kRequestTimeout);
    const auto out = encode_reply(reply);
    auto [wec, written] = co_await asio::async_write(stream, asio::buffer(out), use_tuple);
    (void)written;
    timer.cancel();
    if (!wec) {
        // Le client ferme après avoir lu la réponse : on attend sa fermeture
        // pour ne pas perdre de données non lues (named pipe).
        arm(timer, stream, std::chrono::seconds(2));
        char c;
        co_await stream.async_read_some(asio::buffer(&c, 1), use_tuple);
        timer.cancel();
    }
    std::error_code ignored;
    stream.close(ignored);
}

// Lit une réponse « OK <n>\n<corps> » dans data ; std::nullopt si incomplète.
// error est renseigné si l'en-tête est invalide.
inline std::optional<Reply> decode_reply(const std::string& data, std::string& error) {
    const auto eol = data.find('\n');
    if (eol == std::string::npos) {
        if (data.size() > 64) error = "réponse invalide";
        return std::nullopt;
    }
    const std::string header = data.substr(0, eol);
    Reply r;
    std::string size;
    if (header.rfind("OK ", 0) == 0) {
        r.ok = true;
        size = header.substr(3);
    } else if (header.rfind("ERREUR ", 0) == 0) {
        r.ok = false;
        size = header.substr(7);
    } else {
        error = "réponse invalide";
        return std::nullopt;
    }
    std::size_t length = 0;
    try {
        length = std::stoul(size);
    } catch (const std::exception&) {
        error = "réponse invalide";
        return std::nullopt;
    }
    if (data.size() < eol + 1 + length) return std::nullopt;
    r.body = data.substr(eol + 1, length);
    return r;
}

}  // namespace tlsrelay::admin::detail
