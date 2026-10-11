#include "tlsrelay/admin/admin.hpp"

namespace tlsrelay::admin {

std::string default_endpoint(const std::string& instance) {
#ifdef _WIN32
    return "\\\\.\\pipe\\tlsrelay-" + instance;
#else
    return "/run/tlsrelay/" + instance + ".sock";
#endif
}

std::string endpoint_for(const Config& config) {
    return config.admin.endpoint.value_or(default_endpoint(config.instance));
}

std::optional<Request> parse_request(std::string_view line) {
    if (!line.empty() && line.back() == '\n') line.remove_suffix(1);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    Request r;
    std::string word;
    auto flush = [&] {
        if (word.empty()) return;
        if (r.command.empty()) r.command = std::move(word);
        else r.args.push_back(std::move(word));
        word.clear();
    };
    for (const char c : line) {
        if (static_cast<unsigned char>(c) < 0x20 && c != '\t') return std::nullopt;
        if (c == ' ' || c == '\t') flush();
        else word += c;
    }
    flush();
    if (r.command.empty()) return std::nullopt;
    return r;
}

std::string encode_reply(const Reply& reply) {
    return std::string(reply.ok ? "OK " : "ERREUR ") + std::to_string(reply.body.size()) + "\n" + reply.body;
}

}  // namespace tlsrelay::admin
