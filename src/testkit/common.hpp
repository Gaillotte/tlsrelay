#pragma once

// Outils communs de tlsrelay-testkit : exécution multi-thread, données
// pseudo-aléatoires reproductibles, empreintes, statistiques.

#include <asio/as_tuple.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/use_awaitable.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace testkit {

using asio::ip::tcp;
using Clock = std::chrono::steady_clock;
inline constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

// Exécute io sur n threads jusqu'à épuisement du travail.
inline void run_threads(asio::io_context& io, unsigned n) {
    if (n == 0) n = std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::thread> threads;
    for (unsigned i = 1; i < n; ++i) threads.emplace_back([&io] { io.run(); });
    io.run();
    for (auto& t : threads) t.join();
}

// Générateur xorshift64* : flux reproductible pour une graine donnée.
class Pattern {
public:
    explicit Pattern(std::uint64_t seed) : state_(seed * 0x9E3779B97F4A7C15ULL + 1) {}
    void fill(unsigned char* data, std::size_t size) {
        for (std::size_t i = 0; i < size; i += 8) {
            state_ ^= state_ >> 12;
            state_ ^= state_ << 25;
            state_ ^= state_ >> 27;
            const std::uint64_t v = state_ * 0x2545F4914F6CDD1DULL;
            for (std::size_t j = 0; j < 8 && i + j < size; ++j) data[i + j] = static_cast<unsigned char>(v >> (8 * j));
        }
    }

private:
    std::uint64_t state_;
};

// Empreinte SHA-256 incrémentale.
class Digest {
public:
    Digest() : ctx_(EVP_MD_CTX_new(), EVP_MD_CTX_free) { EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr); }
    void update(const void* data, std::size_t size) { EVP_DigestUpdate(ctx_.get(), data, size); }
    std::string hex() {
        unsigned char out[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        EVP_DigestFinal_ex(ctx_.get(), out, &len);
        static constexpr char digits[] = "0123456789abcdef";
        std::string s;
        for (unsigned i = 0; i < len; ++i) {
            s += digits[out[i] >> 4];
            s += digits[out[i] & 0xf];
        }
        return s;
    }

private:
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_;
};

// Percentile (0-100) d'un échantillon de durées en microsecondes.
inline double percentile(std::vector<double> values, double p) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const auto rank = static_cast<std::size_t>(p / 100.0 * static_cast<double>(values.size() - 1) + 0.5);
    return values[std::min(rank, values.size() - 1)];
}

inline double micros(Clock::duration d) {
    return std::chrono::duration<double, std::micro>(d).count();
}

}  // namespace testkit
