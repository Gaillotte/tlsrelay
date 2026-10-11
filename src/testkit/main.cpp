// tlsrelay-testkit : outillage de test de tlsrelay (PLAN §5).
//   echo       destination d'écho
//   load       N canaux simultanés, empreinte SHA-256 par canal
//   throughput débit soutenu
//   latency    aller-retour de petits messages
//   proxy      perturbations réseau (latence, débit, coupures, lien muet)
//   pki        PKI de test (mini-AC, générations serveur et client)

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
        std::cerr << "erreur : adresse invalide « " << text << " » (hôte:port)\n";
        return std::nullopt;
    }
    try {
        return testkit::resolve(ep->host, ep->port);
    } catch (const std::exception& e) {
        std::cerr << "erreur : " << text << " : " << e.what() << '\n';
        return std::nullopt;
    }
}

std::optional<std::chrono::milliseconds> duration(const std::string& text) {
    const auto d = tlsrelay::parse_duration(text);
    if (!d) std::cerr << "erreur : durée invalide « " << text << " »\n";
    return d;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    CLI::App app{"tlsrelay-testkit : outillage de test de tlsrelay"};
    app.require_subcommand(1);
    app.fallthrough();  // --json et --threads aussi après la sous-commande
    unsigned threads = 0;
    bool json = false;
    app.add_option("--threads", threads, "Threads (défaut : nombre de cœurs)");
    app.add_flag("--json", json, "Résultat au format JSON");

    std::string listen, target;
    auto* echo = app.add_subcommand("echo", "Destination d'écho");
    echo->add_option("--listen", listen, "Adresse d'écoute (hôte:port)")->required();
    bool half_duplex = false;
    echo->add_flag("--half-duplex", half_duplex, "Ne lit plus tant que la réponse n'est pas écrite (destination à l'alternat)");

    testkit::LoadOptions load_options;
    std::string bytes = "1MiB", hold = "0s";
    auto* load = app.add_subcommand("load", "Canaux simultanés, empreinte SHA-256 vérifiée par canal");
    load->add_option("--target", target, "Port d'entrée (tlsrelay client ou écho)")->required();
    load->add_option("--channels", load_options.channels, "Nombre de canaux (défaut : 100)");
    load->add_option("--bytes", bytes, "Octets par canal et par sens (défaut : 1MiB)");
    load->add_option("--batch", load_options.batch, "Canaux ouverts par vague (défaut : 200 ; 0 : tous)");
    load->add_option("--hold", hold, "Maintien des canaux ouverts avant le transfert (ex. 30s)");

    int channels = 1;
    std::string seconds = "10s";
    auto* throughput = app.add_subcommand("throughput", "Débit soutenu");
    throughput->add_option("--target", target, "Port d'entrée")->required();
    throughput->add_option("--channels", channels, "Canaux (défaut : 1)");
    throughput->add_option("--duration", seconds, "Durée (défaut : 10s)");
    double rate_mbps = 0;
    throughput->add_option("--rate", rate_mbps, "Débit d'émission de chaque canal, en Mbit/s (défaut : sans limite)");

    int count = 5000;
    std::size_t size = 64;
    auto* latency = app.add_subcommand("latency", "Aller-retour de petits messages");
    latency->add_option("--target", target, "Port d'entrée")->required();
    latency->add_option("--count", count, "Mesures (défaut : 5000)");
    latency->add_option("--size", size, "Taille du message (défaut : 64)");

    testkit::ProxyOptions proxy_options;
    std::string delay = "0ms", cut_every = "0s";
    auto* proxy = app.add_subcommand("proxy", "Perturbations réseau entre deux tlsrelay");
    proxy->add_option("--listen", listen, "Adresse d'écoute")->required();
    proxy->add_option("--target", target, "Destination")->required();
    proxy->add_option("--delay", delay, "Latence ajoutée par paquet (ex. 20ms)");
    proxy->add_option("--rate", proxy_options.rate_mbps, "Débit maximal en Mbit/s par sens");
    proxy->add_option("--cut-every", cut_every, "Coupure (RST) de toutes les connexions à cet intervalle");
    proxy->add_flag("--freeze", proxy_options.freeze, "Lien muet au lieu d'une coupure");

    testkit::PkiOptions pki_options;
    auto* pki = app.add_subcommand("pki", "PKI de test ; relancée, ajoute une génération et l'active");
    pki->add_option("--out", pki_options.out, "Répertoire")->required();
    pki->add_option("--server-subject", pki_options.server_subject, "Sujet du serveur");
    pki->add_option("--server-san", pki_options.server_sans, "SAN du serveur (défaut : relay.test, 127.0.0.1, ::1)");
    pki->add_option("--client-subject", pki_options.client_subject, "Sujet du client");

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
        return testkit::run_proxy(*l, *ep, proxy_options, threads);
    }
    return 2;
}
