// Trafic de test : destination d'écho, charge massive avec empreinte par
// canal, débit, latence aller-retour.

#include "traffic.hpp"

#include <asio/co_spawn.hpp>
#include <asio/read.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <asio/write.hpp>

#include <atomic>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <sstream>

namespace testkit {
namespace {

using namespace asio::experimental::awaitable_operators;
constexpr std::size_t kChunk = 16ULL * 1024;

std::string json_escape(const std::string& s) {
    std::string out;
    for (const char c : s) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
    }
    return out;
}

asio::awaitable<void> echo_connection(tcp::socket socket) {
    std::vector<unsigned char> buffer(64ULL * 1024);
    for (;;) {
        auto [ec, n] = co_await socket.async_read_some(asio::buffer(buffer), use_tuple);
        if (ec) break;
        auto [wec, w] = co_await asio::async_write(socket, asio::buffer(buffer.data(), n), use_tuple);
        (void)w;
        if (wec) break;
    }
    std::error_code ignored;
    socket.shutdown(tcp::socket::shutdown_send, ignored);
}

asio::awaitable<void> echo_accept(tcp::acceptor& acceptor, asio::io_context& io) {
    for (;;) {
        auto [ec, socket] = co_await acceptor.async_accept(asio::make_strand(io), use_tuple);
        if (ec) {
            if (!acceptor.is_open()) co_return;
            continue;
        }
        std::error_code ignored;
        socket.set_option(tcp::no_delay(true), ignored);
        auto ex = socket.get_executor();
        asio::co_spawn(ex, echo_connection(std::move(socket)), asio::detached);
    }
}

// Écrit size octets du motif seed (ou jusqu'à deadline), en calculant l'empreinte.
asio::awaitable<std::uint64_t> send_pattern(tcp::socket& s, std::uint64_t size, std::uint64_t seed,
                                            Clock::time_point deadline, std::string& digest) {
    Pattern pattern(seed);
    Digest d;
    std::vector<unsigned char> chunk(kChunk);
    std::uint64_t sent = 0;
    while (sent < size && Clock::now() < deadline) {
        const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(kChunk, size - sent));
        pattern.fill(chunk.data(), n);
        d.update(chunk.data(), n);
        auto [ec, w] = co_await asio::async_write(s, asio::buffer(chunk.data(), n), use_tuple);
        if (ec) break;
        sent += w;
    }
    std::error_code ignored;
    s.shutdown(tcp::socket::shutdown_send, ignored);
    digest = d.hex();
    co_return sent;
}

asio::awaitable<std::uint64_t> receive_all(tcp::socket& s, std::string& digest, std::string& error) {
    Digest d;
    std::vector<unsigned char> buffer(64ULL * 1024);
    std::uint64_t received = 0;
    for (;;) {
        auto [ec, n] = co_await s.async_read_some(asio::buffer(buffer), use_tuple);
        if (ec) {
            if (ec != asio::error::eof) error = ec.message();
            break;
        }
        d.update(buffer.data(), n);
        received += n;
    }
    digest = d.hex();
    co_return received;
}

struct LoadState {
    std::atomic<int> connected{0};
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::mutex mutex;
    std::vector<double> connect_us;
    std::vector<std::string> errors;
    std::atomic<int> ok{0};
    std::atomic<int> failed{0};
    std::atomic<std::uint64_t> bytes{0};
    Clock::time_point transfer_start{};  // écrit avant go, lu après la fin des threads
};

asio::awaitable<void> load_channel(tcp::endpoint target, const LoadOptions& o, std::uint64_t seed, LoadState& st) {
    auto ex = co_await asio::this_coro::executor;
    tcp::socket s(ex);
    auto fail = [&](const std::string& why) {
        ++st.failed;
        std::lock_guard lock(st.mutex);
        if (st.errors.size() < 10) st.errors.push_back("canal " + std::to_string(seed) + " : " + why);
    };
    const auto t0 = Clock::now();
    auto [cec] = co_await s.async_connect(target, use_tuple);
    if (cec) {
        fail("connexion : " + cec.message());
        ++st.ready;
        co_return;
    }
    std::error_code ignored;
    s.set_option(tcp::no_delay(true), ignored);
    // Premier aller-retour : le tunnel est établi de bout en bout.
    unsigned char probe = 0x5a, back = 0;
    auto [wec, w] = co_await asio::async_write(s, asio::buffer(&probe, 1), use_tuple);
    (void)w;
    auto [rec, r] = co_await asio::async_read(s, asio::buffer(&back, 1), use_tuple);
    (void)r;
    if (wec || rec || back != probe) {
        fail("tunnel non établi : " + (wec ? wec.message() : rec ? rec.message() : std::string("écho incorrect")));
        ++st.ready;
        co_return;
    }
    {
        std::lock_guard lock(st.mutex);
        st.connect_us.push_back(micros(Clock::now() - t0));
    }
    ++st.connected;
    ++st.ready;
    // Tous les canaux ouverts en même temps avant le transfert.
    asio::steady_timer wait(ex);
    while (!st.go) {
        wait.expires_after(std::chrono::milliseconds(10));
        co_await wait.async_wait(use_tuple);
    }
    if (o.hold > Clock::duration::zero()) {
        wait.expires_after(o.hold);
        co_await wait.async_wait(use_tuple);
    }
    std::string sent_digest, received_digest, error;
    const auto result = co_await (send_pattern(s, o.bytes, seed, Clock::time_point::max(), sent_digest) &&
                                  receive_all(s, received_digest, error));
    const auto [sent, received] = result;
    st.bytes += received;
    if (received != o.bytes || sent != o.bytes) fail("reçu " + std::to_string(received) + " / " + std::to_string(o.bytes) +
                                                      " octets" + (error.empty() ? "" : " (" + error + ")"));
    else if (sent_digest != received_digest) fail("empreinte différente");
    else ++st.ok;
}

asio::awaitable<void> ramp(tcp::endpoint target, const LoadOptions& o, LoadState& st, asio::io_context& io) {
    asio::steady_timer pause(co_await asio::this_coro::executor);
    for (int i = 0; i < o.channels; ++i) {
        asio::co_spawn(asio::make_strand(io), load_channel(target, o, static_cast<std::uint64_t>(i) + 1, st),
                       asio::detached);
        if (o.batch > 0 && (i + 1) % o.batch == 0) {
            // Ouverture par vagues : la file d'attente d'acceptation n'est pas saturée.
            while (st.ready.load() < i + 1) {
                pause.expires_after(std::chrono::milliseconds(5));
                co_await pause.async_wait(use_tuple);
            }
        }
    }
    while (st.ready.load() < o.channels) {
        pause.expires_after(std::chrono::milliseconds(5));
        co_await pause.async_wait(use_tuple);
    }
    st.transfer_start = Clock::now();
    st.go = true;
}

}  // namespace

tcp::endpoint resolve(const std::string& host, std::uint16_t port) {
    asio::io_context io;
    tcp::resolver resolver(io);
    return *resolver.resolve(host, std::to_string(port)).begin();
}

int run_echo(const tcp::endpoint& listen, unsigned threads) {
    asio::io_context io;
    tcp::acceptor acceptor(io);
    acceptor.open(listen.protocol());
    acceptor.set_option(tcp::acceptor::reuse_address(true));
    acceptor.bind(listen);
    acceptor.listen(asio::socket_base::max_listen_connections);
    std::cout << "écho en écoute sur " << acceptor.local_endpoint() << '\n' << std::flush;
    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](std::error_code, int) {
        std::error_code ignored;
        acceptor.close(ignored);
        io.stop();
    });
    asio::co_spawn(io, echo_accept(acceptor, io), asio::detached);
    run_threads(io, threads);
    return 0;
}

int run_load(const tcp::endpoint& target, const LoadOptions& o) {
    asio::io_context io;
    LoadState st;
    const auto start = Clock::now();
    asio::co_spawn(io, ramp(target, o, st, io), asio::detached);
    run_threads(io, o.threads);
    const auto end = Clock::now();
    const double seconds = std::chrono::duration<double>(end - st.transfer_start).count();
    const double mbits = seconds > 0 ? static_cast<double>(st.bytes.load()) * 8 / 1e6 / seconds : 0;
    const double total = std::chrono::duration<double>(end - start).count();

    if (o.json) {
        std::cout << "{\"channels\":" << o.channels << ",\"connected\":" << st.connected << ",\"ok\":" << st.ok
                  << ",\"failed\":" << st.failed << ",\"bytes\":" << st.bytes << ",\"transfer_seconds\":" << seconds
                  << ",\"total_seconds\":" << total << ",\"mbit_per_s\":" << mbits
                  << ",\"connect_p50_us\":" << percentile(st.connect_us, 50)
                  << ",\"connect_p99_us\":" << percentile(st.connect_us, 99) << ",\"errors\":[";
        for (std::size_t i = 0; i < st.errors.size(); ++i) {
            std::cout << (i ? "," : "") << '"' << json_escape(st.errors[i]) << '"';
        }
        std::cout << "]}" << '\n' << std::flush;
    } else {
        std::printf("canaux : %d demandés, %d ouverts simultanément, %d intègres, %d en échec\n", o.channels,
                    st.connected.load(), st.ok.load(), st.failed.load());
        std::printf("transfert : %.1f Mio en %.2f s, %.1f Mbit/s agrégés ; établissement p50 %.0f µs, p99 %.0f µs\n",
                    static_cast<double>(st.bytes.load()) / (1 << 20), seconds, mbits, percentile(st.connect_us, 50),
                    percentile(st.connect_us, 99));
        for (const auto& e : st.errors) std::printf("  %s\n", e.c_str());
    }
    return st.failed == 0 && st.ok == o.channels ? 0 : 1;
}

int run_throughput(const tcp::endpoint& target, int channels, std::chrono::milliseconds duration, unsigned threads, bool json) {
    asio::io_context io;
    std::atomic<std::uint64_t> total{0};
    std::atomic<int> intact{0};
    std::mutex errors_mutex;
    std::vector<std::string> errors;
    const auto start = Clock::now();
    const auto deadline = start + duration;
    for (int i = 0; i < channels; ++i) {
        asio::co_spawn(
            asio::make_strand(io),
            [&, i, target]() -> asio::awaitable<void> {
                tcp::socket s(co_await asio::this_coro::executor);
                auto [cec] = co_await s.async_connect(target, use_tuple);
                if (cec) {
                    std::lock_guard lock(errors_mutex);
                    errors.push_back("canal " + std::to_string(i) + " : connexion impossible : " + cec.message());
                    co_return;
                }
                std::error_code ignored;
                s.set_option(tcp::no_delay(true), ignored);
                std::string sent_digest, received_digest, error;
                const auto result = co_await (send_pattern(s, ~std::uint64_t{0}, static_cast<std::uint64_t>(i) + 1,
                                                           deadline, sent_digest) &&
                                              receive_all(s, received_digest, error));
                total += std::get<1>(result);
                if (std::get<0>(result) == std::get<1>(result) && sent_digest == received_digest) {
                    ++intact;
                    co_return;
                }
                const double at = std::chrono::duration<double>(Clock::now() - start).count();
                std::lock_guard lock(errors_mutex);
                errors.push_back("canal " + std::to_string(i) + " : " + std::to_string(std::get<0>(result)) +
                                 " octets émis, " + std::to_string(std::get<1>(result)) + " reçus, arrêt à " +
                                 std::to_string(static_cast<int>(at)) + " s" + (error.empty() ? "" : " : " + error));
            },
            asio::detached);
    }
    run_threads(io, threads);
    const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
    const double mbits = static_cast<double>(total.load()) * 8 / 1e6 / seconds;
    if (json) {
        std::cout << "{\"channels\":" << channels << ",\"intact\":" << intact << ",\"bytes\":" << total
                  << ",\"seconds\":" << seconds << ",\"mbit_per_s\":" << mbits
                  << ",\"mbit_per_s_per_channel\":" << mbits / channels << ",\"errors\":[";
        for (std::size_t k = 0; k < errors.size(); ++k) std::cout << (k ? "," : "") << '"' << json_escape(errors[k]) << '"';
        std::cout << "]}" << '\n' << std::flush;
    } else {
        std::printf("débit : %.1f Mbit/s sur %d canal(aux), soit %.1f Mbit/s par canal (%.1f Mio en %.2f s, %d/%d "
                    "intègres)\n",
                    mbits, channels, mbits / channels, static_cast<double>(total.load()) / (1 << 20), seconds,
                    intact.load(), channels);
        for (const auto& e : errors) std::printf("  %s\n", e.c_str());
    }
    return intact == channels ? 0 : 1;
}

int run_latency(const tcp::endpoint& target, int count, std::size_t size, bool json) {
    asio::io_context io;
    std::vector<double> rtt;
    std::string error;
    asio::co_spawn(
        io,
        [&]() -> asio::awaitable<void> {
            tcp::socket s(co_await asio::this_coro::executor);
            auto [cec] = co_await s.async_connect(target, use_tuple);
            if (cec) {
                error = cec.message();
                co_return;
            }
            s.set_option(tcp::no_delay(true));
            std::vector<unsigned char> out(size, 0x42), in(size);
            for (int i = -100; i < count; ++i) {  // 100 échanges d'échauffement
                const auto t0 = Clock::now();
                auto [wec, w] = co_await asio::async_write(s, asio::buffer(out), use_tuple);
                (void)w;
                auto [rec, r] = co_await asio::async_read(s, asio::buffer(in), use_tuple);
                (void)r;
                if (wec || rec) {
                    error = (wec ? wec : rec).message();
                    co_return;
                }
                if (i >= 0) rtt.push_back(micros(Clock::now() - t0));
            }
        },
        asio::detached);
    io.run();
    if (!error.empty()) {
        std::cerr << "erreur : " << error << '\n';
        return 1;
    }
    if (json) {
        std::cout << "{\"count\":" << count << ",\"size\":" << size << ",\"p50_us\":" << percentile(rtt, 50)
                  << ",\"p90_us\":" << percentile(rtt, 90) << ",\"p99_us\":" << percentile(rtt, 99)
                  << ",\"max_us\":" << percentile(rtt, 100) << "}" << '\n' << std::flush;
    } else {
        std::printf("aller-retour (%zu octets, %d mesures) : p50 %.0f µs, p90 %.0f µs, p99 %.0f µs, max %.0f µs\n", size,
                    count, percentile(rtt, 50), percentile(rtt, 90), percentile(rtt, 99), percentile(rtt, 100));
    }
    return 0;
}

}  // namespace testkit
