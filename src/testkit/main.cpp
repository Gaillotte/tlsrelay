// tlsrelay-testkit: tlsrelay test tooling (PLAN §5).
//   echo       echo destination
//   load       N simultaneous channels, SHA-256 hash per channel
//   throughput sustained throughput
//   latency    round trip of small messages
//   proxy      network disturbances (latency, throughput, cuts, silent link)
//   pki        test PKI (mini-CA, server and client generations)

#include "pki.hpp"
#include "proxy.hpp"
#include "traffic.hpp"

#include "tlsrelay/endpoint.hpp"
#include "tlsrelay/units.hpp"

#include <CLI/CLI.hpp>

#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

std::optional<testkit::tcp::endpoint> endpoint(const std::string& text) {
    const auto ep = tlsrelay::parse_endpoint(text);
    if (!ep || ep->port == 0) {
        std::cerr << "error: invalid address \"" << text << "\" (host:port)\n";
        return std::nullopt;
    }
    try {
        return testkit::resolve(ep->host, ep->port);
    } catch (const std::exception& e) {
        std::cerr << "error: " << text << ": " << e.what() << '\n';
        return std::nullopt;
    }
}

std::optional<std::chrono::milliseconds> duration(const std::string& text) {
    const auto d = tlsrelay::parse_duration(text);
    if (!d) std::cerr << "error: invalid duration \"" << text << "\"\n";
    return d;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    CLI::App app{"tlsrelay-testkit: tlsrelay test tooling"};
    app.require_subcommand(1);
    app.fallthrough();  // --json and --threads also after the subcommand
    unsigned threads = 0;
    bool json = false;
    app.add_option("--threads", threads, "Threads (default: number of cores)");
    app.add_flag("--json", json, "Result in JSON format");

    std::string listen, target;
    auto* echo = app.add_subcommand("echo", "Echo destination");
    echo->add_option("--listen", listen, "Listen address (host:port)")->required();
    bool half_duplex = false;
    echo->add_flag("--half-duplex", half_duplex, "Stops reading until the reply is written (half-duplex destination)");

    testkit::LoadOptions load_options;
    std::string bytes = "1MiB", hold = "0s";
    auto* load = app.add_subcommand("load", "Simultaneous channels, SHA-256 hash checked per channel");
    load->add_option("--target", target, "Entry port (tlsrelay client or echo)")->required();
    load->add_option("--channels", load_options.channels, "Number of channels (default: 100)");
    load->add_option("--bytes", bytes, "Bytes per channel and per direction (default: 1MiB)");
    load->add_option("--batch", load_options.batch, "Channels opened per wave (default: 200; 0: all)");
    load->add_option("--hold", hold, "Keep the channels open before the transfer (e.g. 30s)");

    int channels = 1;
    std::string seconds = "10s";
    auto* throughput = app.add_subcommand("throughput", "Sustained throughput");
    throughput->add_option("--target", target, "Entry port")->required();
    throughput->add_option("--channels", channels, "Channels (default: 1)");
    throughput->add_option("--duration", seconds, "Duration (default: 10s)");
    double rate_mbps = 0;
    throughput->add_option("--rate", rate_mbps, "Send rate of each channel, in Mbit/s (default: unlimited)");

    int count = 5000;
    std::size_t size = 64;
    auto* latency = app.add_subcommand("latency", "Round trip of small messages");
    latency->add_option("--target", target, "Entry port")->required();
    latency->add_option("--count", count, "Measurements (default: 5000)");
    latency->add_option("--size", size, "Message size (default: 64)");

    testkit::ProxyOptions proxy_options;
    std::string delay = "0ms", cut_every = "0s";
    auto* proxy = app.add_subcommand("proxy", "Network disturbances between two tlsrelay instances");
    proxy->add_option("--listen", listen, "Listen address")->required();
    proxy->add_option("--target", target, "Destination")->required();
    proxy->add_option("--delay", delay, "Latency added per packet (e.g. 20ms)");
    proxy->add_option("--rate", proxy_options.rate_mbps, "Maximum throughput in Mbit/s per direction");
    proxy->add_option("--cut-every", cut_every, "Cut (RST) all connections at this interval");
    proxy->add_flag("--freeze", proxy_options.freeze, "Silent link instead of a cut");
    std::string proxy_source;
    proxy->add_option("--source", proxy_source, "Source address of the connections to the destination");

    testkit::PkiOptions pki_options;
    auto* pki = app.add_subcommand("pki", "Test PKI; when run again, adds a generation and activates it");
    pki->add_option("--out", pki_options.out, "Directory")->required();
    pki->add_option("--server-subject", pki_options.server_subject, "Server subject");
    pki->add_option("--server-san", pki_options.server_sans, "Server SANs (default: relay.test, 127.0.0.1, ::1)");
    pki->add_option("--client-subject", pki_options.client_subject, "Client subject");

    CLI11_PARSE(app, argc, argv);

    if (*pki) return testkit::run_pki(pki_options);
    if (*echo) {
        const auto ep = endpoint(listen);
        return ep ? testkit::run_echo(*ep, threads, half_duplex) : 2;
    }
    const auto ep = endpoint(target);
    if (!ep) return 2;
    if (*load) {
        const auto b = tlsrelay::parse_size(bytes);
        const auto h = duration(hold);
        if (!b || !h) return 2;
        load_options.bytes = *b;
        load_options.hold = *h;
        load_options.threads = threads;
        load_options.json = json;
        return testkit::run_load(*ep, load_options);
    }
    if (*throughput) {
        const auto d = duration(seconds);
        return d ? testkit::run_throughput(*ep, channels, *d, threads, json, rate_mbps) : 2;
    }
    if (*latency) return testkit::run_latency(*ep, count, size, json);
    if (*proxy) {
        const auto l = endpoint(listen);
        const auto d = duration(delay);
        const auto c = duration(cut_every);
        if (!l || !d || !c) return 2;
        proxy_options.delay = *d;
        proxy_options.cut_every = *c;
        if (!proxy_source.empty()) {
            std::error_code ec;
            proxy_options.source = asio::ip::make_address(proxy_source, ec);
            if (ec) {
                std::cerr << "invalid source address: " << proxy_source << '\n';
                return 2;
            }
        }
        return testkit::run_proxy(*l, *ep, proxy_options, threads);
    }
    return 2;
}
