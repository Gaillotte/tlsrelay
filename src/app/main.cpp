// tlsrelay entry point (SPEC §10). Available commands:
//   tlsrelay run -c <config> [--instance N] [-v|-vv|-q]
//   tlsrelay check-config -c <config>
//   tlsrelay check-pki -c <config> [generation]
//   tlsrelay pki activate -c <config> <generation> [--force]
//   tlsrelay pki gen-csr -c <config> --subject DN [--san ...]
//   tlsrelay pki install -c <config> [--generation vN] [--from kit] [--cert --chain --roots --issuer]
//   tlsrelay pki crl -c <config> <file>
//   tlsrelay ca init --dir <ca> [--org name]
//   tlsrelay ca sign --dir <ca> --role server|client --csr <file> [--san ...] [--days N] [--renew] --out <kit>
//   tlsrelay ca list --dir <ca>
//   tlsrelay ca revoke --dir <ca> --serial S [--reason reason] [--days N] [--out crl.pem]
//   tlsrelay ca crl --dir <ca> [--days N] [--out crl.pem]
//   tlsrelay ca audit --dir <ca>
//   tlsrelay ca root-change --dir <old ca> --new <new ca> --out <directory>
//   tlsrelay status|channels|metrics|kill|log-reopen [target]
//   tlsrelay stop [target] [--timeout duration]
//   tlsrelay reload [target] [--kill-old]
//   tlsrelay log-level [target] <level|category=level>
//   tlsrelay start|restart --instance N [--timeout duration]
//   tlsrelay service install --instance N [-c config] [--boot]
//   tlsrelay service uninstall --instance N
//   tlsrelay version
// target: --instance N (default: default), -c <config> or --admin <endpoint>.

#include "passphrase.hpp"
#include "platform.hpp"

#include "tlsrelay/admin/admin.hpp"
#include "tlsrelay/config.hpp"
#include "tlsrelay/logging.hpp"
#include "tlsrelay/openssl_info.hpp"
#include "tlsrelay/pki/audit.hpp"
#include "tlsrelay/pki/authority.hpp"
#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/pki/request.hpp"
#include "tlsrelay/pki/revocation.hpp"
#include "tlsrelay/relay/service.hpp"
#include "tlsrelay/version.hpp"

#include <CLI/CLI.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

// Exit codes
constexpr int kExitOk = 0;
constexpr int kExitRuntime = 1;
constexpr int kExitConfig = 2;

void print_issues(const tlsrelay::LoadResult& result) {
    for (const auto& e : result.errors) std::cerr << "error: " << e.path << ": " << e.message << '\n';
    for (const auto& w : result.warnings) std::cerr << "warning: " << w.path << ": " << w.message << '\n';
}

int cmd_check_config(const std::string& path) {
    const auto result = tlsrelay::load_config_file(path);
    print_issues(result);
    if (!result.config) {
        std::cerr << result.errors.size() << " error(s) in " << path << '\n';
        return kExitConfig;
    }
    std::cout << "valid configuration: " << path << '\n';
    return kExitOk;
}

// Loads the configuration and derives the PKI requirements from it; nullopt on error (already printed).
std::optional<std::pair<tlsrelay::Config, tlsrelay::pki::Requirements>> pki_context(const std::string& path) {
    const auto result = tlsrelay::load_config_file(path);
    print_issues(result);
    if (!result.config) return std::nullopt;
    const auto req = tlsrelay::pki::requirements_for(*result.config);
    if (!req || !result.config->credentials) {
        std::cerr << "error: no tls or mtls port configured in " << path << '\n';
        return std::nullopt;
    }
    return std::pair{*result.config, *req};
}

int cmd_check_pki(const std::string& config_path, std::string name) {
    const auto ctx = pki_context(config_path);
    if (!ctx) return kExitConfig;
    const auto& root = ctx->first.credentials->pki_root;
    if (name.empty()) {
        std::ifstream in(std::filesystem::path(root) / "current");
        std::getline(in, name);
    }
    const auto result = tlsrelay::pki::check_candidate(root, name, ctx->second);
    for (const auto& e : result.errors) std::cerr << "error: " << e.path << ": " << e.message << '\n';
    for (const auto& w : result.warnings) std::cerr << "warning: " << w.path << ": " << w.message << '\n';
    if (!result.generation) {
        std::cerr << "generation \"" << name << "\" rejected\n";
        return kExitConfig;
    }
    const auto& gen = *result.generation;
    std::cout << "generation \"" << name << "\" valid";
    if (gen.cert) std::cout << ": certificate " << tlsrelay::tls::subject_of(gen.cert.get()) << ", valid until "
                            << tlsrelay::tls::not_after_of(gen.cert.get());
    std::cout << '\n';
    // CRL in place: checked for this generation (only if it verifies its peers).
    const auto crl = std::filesystem::path(root) / tlsrelay::pki::kCrlFile;
    if (ctx->second.trust && std::filesystem::exists(crl)) {
        const auto revocations = tlsrelay::pki::load_revocations(crl, gen);
        for (const auto& e : revocations.errors) std::cerr << "error: " << e.path << ": " << e.message << '\n';
        for (const auto& w : revocations.warnings) std::cerr << "warning: " << w.path << ": " << w.message << '\n';
        if (!revocations.list) {
            std::cerr << "CRL rejected\n";
            return kExitConfig;
        }
        std::cout << "CRL valid: " << revocations.list->size() << " certificate(s) revoked\n";
    }
    return kExitOk;
}

// Checks a CRL file against the current generation, then places it in
// <pki_root>/crl.pem by atomic rename (picked up live).
int cmd_pki_crl(const std::string& config_path, const std::string& file) {
    const auto ctx = pki_context(config_path);
    if (!ctx) return kExitConfig;
    if (!ctx->second.trust) {
        std::cerr << "error: this instance does not verify its peers' certificates: CRL not applicable\n";
        return kExitConfig;
    }
    const std::filesystem::path root = ctx->first.credentials->pki_root;
    const auto current = tlsrelay::pki::load_current_generation(root, ctx->second);
    if (!current.generation) {
        for (const auto& e : current.errors) std::cerr << "error: " << e.path << ": " << e.message << '\n';
        return kExitConfig;
    }
    const auto result = tlsrelay::pki::load_revocations(file, *current.generation);
    for (const auto& e : result.errors) std::cerr << "error: " << e.path << ": " << e.message << '\n';
    for (const auto& w : result.warnings) std::cerr << "warning: " << w.path << ": " << w.message << '\n';
    if (!result.list) {
        std::cerr << "CRL rejected: " << file << '\n';
        return kExitConfig;
    }
    try {
        const auto tmp = root / (std::string(tlsrelay::pki::kCrlFile) + ".tmp");
        std::filesystem::copy_file(file, tmp, std::filesystem::copy_options::overwrite_existing);
        std::filesystem::rename(tmp, root / tlsrelay::pki::kCrlFile);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    std::cout << "CRL installed in " << (root / tlsrelay::pki::kCrlFile).string() << ": "
              << result.list->size() << " certificate(s) revoked; picked up by the running service "
              << "at the next watch check, or with reload\n";
    return kExitOk;
}

int cmd_pki_activate(const std::string& config_path, const std::string& name, bool force) {
    const auto ctx = pki_context(config_path);
    if (!ctx) return kExitConfig;
    const auto& root = ctx->first.credentials->pki_root;
    const auto result = tlsrelay::pki::check_candidate(root, name, ctx->second);
    for (const auto& e : result.errors) std::cerr << "error: " << e.path << ": " << e.message << '\n';
    for (const auto& w : result.warnings) std::cerr << "warning: " << w.path << ": " << w.message << '\n';
    if (!result.generation && !force) {
        std::cerr << "generation \"" << name << "\" not activated (--force to override)\n";
        return kExitConfig;
    }
    try {
        tlsrelay::pki::activate(root, name);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    std::cout << "generation \"" << name << "\" activated in " << root
              << " (picked up by the running service at the next watch check, or with SIGHUP)\n";
    return kExitOk;
}

void print_check(const tlsrelay::pki::LoadResult& result) {
    for (const auto& e : result.errors) std::cerr << "error: " << e.path << ": " << e.message << '\n';
    for (const auto& w : result.warnings) std::cerr << "warning: " << w.path << ": " << w.message << '\n';
}

const char* role_text(tlsrelay::pki::Role role) { return role == tlsrelay::pki::Role::server ? "server" : "client"; }

int cmd_gen_csr(const std::string& config_path, const std::string& subject, const std::vector<std::string>& san_items) {
    const auto ctx = pki_context(config_path);
    if (!ctx) return kExitConfig;
    const auto& [config, req] = *ctx;
    if (!req.identity) {
        std::cerr << "error: this instance does not present a certificate (client without an mtls port): "
                     "only the trust files are needed (tlsrelay pki install --roots --issuer)\n";
        return kExitConfig;
    }
    std::string error;
    const auto sans = tlsrelay::pki::parse_sans(san_items, error);
    if (!sans) {
        std::cerr << "error: " << error << '\n';
        return kExitConfig;
    }
    try {
        const auto result = tlsrelay::pki::generate_csr(config.credentials->pki_root, subject, *sans);
        std::cout << "generation " << result.generation << ": ECDSA P-256 key created (it never leaves this machine)\n"
                  << "signing request: " << result.csr.string() << " (subject " << result.subject << ")\n"
                  << "next steps:\n"
                  << "  1. on the CA workstation: tlsrelay ca sign --dir <ca> --role " << role_text(req.role)
                  << " --csr " << result.csr.string() << (sans->empty() ? std::string() : " --san " + sans->to_openssl())
                  << " --out <kit>\n"
                  << "  2. here: tlsrelay pki install -c " << config_path << " --from <kit>\n"
                  << "  3. here: tlsrelay pki activate -c " << config_path << " " << result.generation << '\n';
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    return kExitOk;
}

int cmd_pki_install(const std::string& config_path, const std::string& generation,
                    const tlsrelay::pki::InstallFiles& files) {
    const auto ctx = pki_context(config_path);
    if (!ctx) return kExitConfig;
    const auto& [config, req] = *ctx;
    try {
        const auto result = tlsrelay::pki::install(config.credentials->pki_root,
                                                   generation.empty() ? std::nullopt : std::optional(generation),
                                                   files, req);
        print_check(result.check);
        if (!result.check.generation) {
            std::cerr << "generation \"" << result.generation << "\" installed but rejected by the checks\n";
            return kExitConfig;
        }
        std::cout << "generation \"" << result.generation << "\" ready; to activate: tlsrelay pki activate -c "
                  << config_path << " " << result.generation << '\n';
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    return kExitOk;
}

int cmd_ca_init(const std::string& dir, const std::string& organization, const std::string& passphrase_file) {
    const auto passphrase = tlsrelay::app::read_passphrase(passphrase_file, true);
    if (!passphrase) return kExitRuntime;
    try {
        tlsrelay::pki::AuthorityOptions options;
        if (!organization.empty()) options.organization = organization;
        tlsrelay::pki::init_authority(dir, *passphrase, options);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    std::cout << "CA created in " << dir << ": root (P-384), Servers CA and Clients CA; keys encrypted\n"
              << "keep this directory and the passphrase on the administration workstation\n";
    return kExitOk;
}

int cmd_ca_sign(const std::string& dir, const std::string& role, const std::string& csr_path,
                const std::vector<std::string>& san_items, int days, bool renew, const std::string& out,
                const std::string& passphrase_file) {
    std::string error;
    const auto sans = tlsrelay::pki::parse_sans(san_items, error);
    if (!sans) {
        std::cerr << "error: " << error << '\n';
        return kExitConfig;
    }
    std::ifstream in(csr_path, std::ios::binary);
    if (!in) {
        std::cerr << "error: cannot read: " << csr_path << '\n';
        return kExitRuntime;
    }
    tlsrelay::pki::SignRequest request;
    request.role = role == "server" ? tlsrelay::pki::Role::server : tlsrelay::pki::Role::client;
    request.csr_pem.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    request.sans = *sans;
    request.days = days;
    request.renew = renew;
    const auto passphrase = tlsrelay::app::read_passphrase(passphrase_file, false);
    if (!passphrase) return kExitRuntime;
    try {
        const auto issued = tlsrelay::pki::sign_request(dir, *passphrase, request);
        tlsrelay::pki::write_bundle(out, issued);
        std::cout << "certificate " << role << " issued: serial " << issued.serial << ", subject " << issued.subject
                  << ", valid until " << issued.not_after << '\n';
        if (!issued.ignored_extensions.empty()) {
            std::string list;
            for (const auto& e : issued.ignored_extensions) list += (list.empty() ? "" : ", ") + e;
            std::cout << "requested extensions ignored (CA policy): " << list << '\n';
        }
        std::cout << "kit to hand over to the instance: " << out
                  << " (cert.pem, chain.pem, trust-roots.pem, trust-issuer.pem); then tlsrelay pki install -c <config> "
                     "--from <kit>\n";
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    return kExitOk;
}

int cmd_ca_list(const std::string& dir) {
    try {
        const auto entries = tlsrelay::pki::list_issued(dir);
        std::cout << entries.size() << " certificate(s) issued\n";
        for (const auto& e : entries) {
            std::cout << e.serial << "  " << e.role << "  " << e.status << "  until " << e.not_after << "  "
                      << e.subject;
            if (!e.revoked_at.empty()) std::cout << "  (revoked on " << e.revoked_at << ", " << e.reason << ")";
            std::cout << '\n';
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    return kExitOk;
}

// Publishes the CRLs and, if requested, writes a copy (to deploy to <pki_root>/crl.pem).
int publish_crl(const std::string& dir, int days, const std::string& out, const std::string& passphrase_file) {
    const auto passphrase = tlsrelay::app::read_passphrase(passphrase_file, false);
    if (!passphrase) return kExitRuntime;
    try {
        const auto crl = tlsrelay::pki::publish_crl(dir, *passphrase, days);
        if (!out.empty()) {
            std::ofstream file(out, std::ios::binary | std::ios::trunc);
            file << crl.pem;
            if (!file) throw std::runtime_error("cannot write: " + out);
        }
        std::cout << "CRL #" << crl.number << " published: " << crl.revoked << " certificate(s) revoked, "
                  << "next update before " << crl.next_update << '\n'
                  << "copy to <pki_root>/crl.pem on each instance: "
                  << (out.empty() ? (std::filesystem::path(dir) / "crl.pem").string() : out) << '\n';
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    return kExitOk;
}

int cmd_ca_revoke(const std::string& dir, const std::string& serial, const std::string& reason_text, int days,
                  const std::string& out, const std::string& passphrase_file) {
    const auto reason = tlsrelay::pki::parse_revocation_reason(reason_text);
    if (!reason) {
        std::cerr << "error: unknown reason \"" << reason_text
                  << "\" (unspecified, keyCompromise, superseded, cessationOfOperation)\n";
        return kExitConfig;
    }
    try {
        const auto entry = tlsrelay::pki::revoke_certificate(dir, serial, *reason);
        std::cout << "certificate " << entry.serial << " (" << entry.role << ", " << entry.subject << ") revoked: "
                  << entry.reason << '\n';
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    return publish_crl(dir, days, out, passphrase_file);
}

int cmd_ca_root_change(const std::string& dir, const std::string& new_dir, const std::string& out) {
    try {
        tlsrelay::pki::write_root_transition(dir, new_dir, out);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    std::cout << "trust files for steps 1 and 2 written to " << out
              << " (server/, client/); full procedure: " << (std::filesystem::path(out) / "README.txt").string()
              << '\n';
    return kExitOk;
}

int cmd_ca_audit(const std::string& dir) {
    try {
        const auto log = tlsrelay::pki::read_audit(dir);
        for (const auto& e : log.entries) {
            std::cout << e.date << "  " << e.operator_name << "  " << e.operation << "  " << e.details << '\n';
        }
        if (log.broken_line) {
            std::cerr << "audit log tampered with at line " << *log.broken_line << ": " << log.problem << '\n';
            return kExitRuntime;
        }
        std::cout << log.entries.size() << " operation(s), hash chain intact\n";
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    return kExitOk;
}

// Runs an instance until it stops. instance: expected name (empty: the one
// in the configuration). control: service manager (nullptr in console mode).
int run_instance(const std::string& path, std::optional<tlsrelay::LogLevel> cli_level, const std::string& instance,
                 tlsrelay::app::ServiceControl* control) {
    using namespace tlsrelay;

    const auto result = load_config_file(path);
    print_issues(result);
    std::string refusal;
    if (result.config && !instance.empty() && instance != result.config->instance) {
        refusal = "configuration " + path + " belongs to instance \"" + result.config->instance +
                  "\", not \"" + instance + "\"";
        std::cerr << "error: " << refusal << '\n';
    }
    if (!result.config || !refusal.empty()) {
#ifdef _WIN32
        // A service has no console: the cause of the failure goes to its default log,
        // whose directory is opened to it at installation.
        if (control) {
            std::ofstream log(app::default_service_log(instance), std::ios::app);
            log << "error: cannot start, configuration " << path << " rejected\n";
            for (const auto& e : result.errors) log << "error: " << e.path << ": " << e.message << '\n';
            if (!refusal.empty()) log << "error: " << refusal << '\n';
        }
#endif
        return kExitConfig;
    }
    Config config = *result.config;
#ifdef _WIN32
    // A Windows service has no console: log in %ProgramData%.
    std::string stderr_replacement;
    if (control) stderr_replacement = app::default_service_log(config.instance).string();
    if (control && config.logging.output == "stderr") config.logging.output = stderr_replacement;
#endif

    if (!openssl_runtime_supported()) {
        std::cerr << "error: OpenSSL 3.0 or later is required (loaded version: " << openssl_runtime_version()
                  << ")\n";
        return kExitRuntime;
    }

    try {
        logging::init(config.logging, cli_level);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
    logging::config().info("tlsrelay {}: configuration loaded from {} (mode={}, instance={})", kVersion, path,
                           to_string(config.mode), config.instance);
    logging::config().info("OpenSSL loaded: {}", openssl_runtime_version());

    try {
        relay::ServiceOptions options;
#ifdef _WIN32
        options.handle_signals = control == nullptr;  // a service takes its orders from the manager
        options.stderr_log_replacement = stderr_replacement;
#endif
        options.config_path = std::filesystem::absolute(path).string();
        relay::Service service(config, options);
        if (control) control->ready([&service] { service.request_stop(); });
        return service.run();
    } catch (const std::exception& e) {
        logging::config().error("{}", e.what());
        // Logging to a file: the startup error is also printed.
        if (config.logging.output != "stderr" && !control) std::cerr << "error: " << e.what() << '\n';
        return kExitRuntime;
    }
}

// Instance targeted by an administration command.
struct Target {
    std::string instance;
    std::string config;
    std::string admin;

    // Channel endpoint; empty if the configuration is unreadable (error printed).
    std::string endpoint() const {
        if (!admin.empty()) return admin;
        if (!config.empty()) {
            const auto result = tlsrelay::load_config_file(config);
            if (!result.config) {
                print_issues(result);
                return {};
            }
            return tlsrelay::admin::endpoint_for(*result.config);
        }
        return tlsrelay::admin::default_endpoint(instance.empty() ? "default" : instance);
    }

    std::string name() const {
        if (!config.empty()) {
            if (const auto result = tlsrelay::load_config_file(config); result.config) return result.config->instance;
        }
        return instance.empty() ? "default" : instance;
    }
};

constexpr auto kCallTimeout = std::chrono::seconds(30);

// Sends a command and prints the reply. Returns the exit code.
int send_command(const std::string& endpoint, const std::string& request, bool print = true) {
    if (endpoint.empty()) return kExitConfig;
    const auto result = tlsrelay::admin::call(endpoint, request, kCallTimeout);
    if (!result.reply) {
        std::cerr << "error: " << result.error << '\n';
        return kExitRuntime;
    }
    if (print) (result.reply->ok ? std::cout : std::cerr) << result.reply->body;
    return result.reply->ok ? kExitOk : kExitRuntime;
}

// Waits until the instance no longer answers (stopped).
bool wait_stopped(const std::string& endpoint, tlsrelay::Duration timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (tlsrelay::admin::call(endpoint, "ping", std::chrono::seconds(2)).unreachable) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

// Waits until the instance answers (started).
bool wait_running(const std::string& endpoint, tlsrelay::Duration timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (tlsrelay::admin::call(endpoint, "ping", std::chrono::seconds(2)).reply) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

int cmd_stop(const Target& target, const std::string& timeout_text) {
    const auto endpoint = target.endpoint();
    if (endpoint.empty()) return kExitConfig;
    std::string request = "stop";
    tlsrelay::Duration wait = std::chrono::minutes(1);
    if (!timeout_text.empty()) {
        const auto timeout = tlsrelay::parse_duration(timeout_text);
        if (!timeout) {
            std::cerr << "error: invalid timeout \"" << timeout_text << "\"\n";
            return kExitConfig;
        }
        request += " " + timeout_text;
        wait = *timeout + std::chrono::seconds(15);
    }
    const auto result = tlsrelay::admin::call(endpoint, request, kCallTimeout);
    if (!result.reply) {
        if (result.unreachable) {
            std::cout << "instance \"" << target.name() << "\" already stopped\n";
            return kExitOk;
        }
        std::cerr << "error: " << result.error << '\n';
        return kExitRuntime;
    }
    std::cout << result.reply->body;
    if (!result.reply->ok) return kExitRuntime;
    if (!wait_stopped(endpoint, wait)) {
        std::cerr << "error: the instance did not stop within the timeout (tlsrelay kill to force)\n";
        return kExitRuntime;
    }
    if (tlsrelay::app::service_installed(target.name())) {
        tlsrelay::app::service_wait_stopped(target.name(), std::chrono::seconds(10));
    }
    std::cout << "instance \"" << target.name() << "\" stopped\n";
    return kExitOk;
}

int cmd_kill(const Target& target) {
    const auto endpoint = target.endpoint();
    if (endpoint.empty()) return kExitConfig;
    const auto result = tlsrelay::admin::call(endpoint, "kill", std::chrono::seconds(5));
    if (result.reply && wait_stopped(endpoint, std::chrono::seconds(10))) {
        if (tlsrelay::app::service_installed(target.name())) {
            tlsrelay::app::service_wait_stopped(target.name(), std::chrono::seconds(10));
        }
        std::cout << "instance \"" << target.name() << "\" stopped immediately\n";
        return kExitOk;
    }
    if (result.unreachable && !tlsrelay::app::service_installed(target.name())) {
        std::cout << "instance \"" << target.name() << "\" already stopped\n";
        return kExitOk;
    }
    // Silent channel: forced stop through the service manager.
    if (tlsrelay::app::service_installed(target.name())) {
        std::cerr << "administration channel not responding: forcing the service to stop\n";
        return tlsrelay::app::service_force_kill(target.name());
    }
    std::cerr << "error: " << (result.reply ? "the instance did not stop" : result.error) << '\n';
    return kExitRuntime;
}

int cmd_start(const std::string& instance, tlsrelay::Duration timeout) {
    if (!tlsrelay::app::service_installed(instance)) {
        std::cerr << "error: instance \"" << instance
                  << "\" is not installed as a service (tlsrelay service install, or tlsrelay run)\n";
        return kExitRuntime;
    }
    const auto endpoint = tlsrelay::admin::default_endpoint(instance);
    if (tlsrelay::admin::call(endpoint, "ping", std::chrono::seconds(2)).reply) {
        std::cout << "instance \"" << instance << "\" already started\n";
        return kExitOk;
    }
    if (const int code = tlsrelay::app::service_start(instance, timeout); code != kExitOk) return code;
    if (!wait_running(endpoint, timeout)) {
        std::cerr << "error: the service was launched but its administration channel does not respond (" << endpoint
                  << ")\n";
        return kExitRuntime;
    }
    std::cout << "instance \"" << instance << "\" started\n";
    return kExitOk;
}

int cmd_install(const std::string& instance, std::string config_path, bool boot) {
    if (!tlsrelay::valid_instance_name(instance)) {
        std::cerr << "error: invalid instance name \"" << instance << "\"\n";
        return kExitConfig;
    }
    if (config_path.empty()) config_path = tlsrelay::app::default_config_path(instance).string();
    const auto absolute = std::filesystem::absolute(config_path);
    const auto result = tlsrelay::load_config_file(absolute);
    print_issues(result);
    if (!result.config) return kExitConfig;
    if (result.config->instance != instance) {
        std::cerr << "error: " << absolute.string() << " declares instance \"" << result.config->instance
                  << "\" (instance: " << instance << " expected)\n";
        return kExitConfig;
    }
    if (result.config->admin.endpoint) {
        std::cerr << "error: a service uses the default administration channel: remove admin.endpoint\n";
        return kExitConfig;
    }
    return tlsrelay::app::service_install(
        {instance, absolute, boot, result.config->limits.shutdown_timeout});
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    tlsrelay::logging::init_default();

    CLI::App app{"tlsrelay: plain TCP / TLS 1.3 / mTLS relay"};
    app.require_subcommand(1);
    app.set_help_all_flag("--help-all", "Help for all commands");

    std::string config_path;
    int verbosity = 0;
    bool quiet = false;

    auto* run = app.add_subcommand("run", "Runs the relay in the foreground (Ctrl+C to stop)");
    run->add_option("-c,--config", config_path, "Configuration file")->required();
    auto* verbose_flag = run->add_flag("-v,--verbose", verbosity, "Verbose mode: -v (debug), -vv (trace)");
    run->add_flag("-q,--quiet", quiet, "Errors only")->excludes(verbose_flag);
    std::string run_instance_name;
    run->add_option("--instance", run_instance_name, "Instance name expected in the configuration (services)");

    auto* check = app.add_subcommand("check-config", "Validates a configuration file without loading it");
    check->add_option("-c,--config", config_path, "Configuration file")->required();

    std::string generation;
    bool force = false;
    auto* check_pki = app.add_subcommand("check-pki", "Validates a PKI generation (the current generation by default)");
    check_pki->add_option("-c,--config", config_path, "Configuration file")->required();
    check_pki->add_option("generation", generation, "Generation name (e.g. v2)");

    auto* pki = app.add_subcommand("pki", "PKI management");
    pki->require_subcommand(1);
    auto* activate = pki->add_subcommand("activate", "Activates a generation (replaces the current file)");
    activate->add_option("-c,--config", config_path, "Configuration file")->required();
    activate->add_option("generation", generation, "Name of the generation to activate (e.g. v2)")->required();
    activate->add_flag("--force", force, "Activates even if the checks fail (emergency only)");
    std::string subject;
    std::vector<std::string> sans;
    auto* gen_csr = pki->add_subcommand("gen-csr", "New generation: P-256 key and certificate signing request (CSR)");
    gen_csr->add_option("-c,--config", config_path, "Configuration file")->required();
    gen_csr->add_option("--subject", subject, "Subject, for example \"CN=relay.example,O=MyCompany\"")->required();
    gen_csr->add_option("--san", sans, "DNS names or IP addresses (advisory: the CA sets those in the certificate)");
    tlsrelay::pki::InstallFiles install_files;
    std::string from, cert, chain, roots, issuer;
    auto* pki_install = pki->add_subcommand("install", "Completes a generation with the signed certificate (without activating it)");
    pki_install->add_option("-c,--config", config_path, "Configuration file")->required();
    pki_install->add_option("--generation", generation, "Generation to complete (default: the pending request)");
    pki_install->add_option("--from", from, "Kit produced by \"ca sign\"");
    pki_install->add_option("--cert", cert, "Signed certificate");
    pki_install->add_option("--chain", chain, "Intermediate CA that signed it");
    pki_install->add_option("--roots", roots, "Trust roots (default: those of the current generation)");
    pki_install->add_option("--issuer", issuer, "CA expected from peers (default: that of the current generation)");
    std::string crl_file;
    auto* pki_crl = pki->add_subcommand("crl", "Checks and installs the CRLs published by the CA (<pki_root>/crl.pem)");
    pki_crl->add_option("-c,--config", config_path, "Configuration file")->required();
    pki_crl->add_option("file", crl_file, "CRL file (ca crl --out)")->required();

    // Mini-CA (administration workstation).
    std::string ca_dir, organization, passphrase_file, role, csr_path, out;
    int days = 365;
    bool renew = false;
    auto* ca = app.add_subcommand("ca", "Mini-CA: root, Servers CA and Clients CA");
    ca->require_subcommand(1);
    auto* ca_init = ca->add_subcommand("init", "Creates the CA (encrypted keys, passphrase prompted)");
    ca_init->add_option("--dir", ca_dir, "CA directory (empty or absent)")->required();
    ca_init->add_option("--org", organization, "Organization (O) of the CA certificates (default: tlsrelay)");
    ca_init->add_option("--passphrase-file", passphrase_file, "Passphrase read from a file");
    auto* ca_sign = ca->add_subcommand("sign", "Signs a request according to the CA policy");
    ca_sign->add_option("--dir", ca_dir, "CA directory")->required();
    ca_sign->add_option("--role", role, "server or client")->required()->check(CLI::IsMember({"server", "client"}));
    ca_sign->add_option("--csr", csr_path, "Signing request (request.csr)")->required();
    ca_sign->add_option("--san", sans, "DNS names or IP addresses of the certificate (required for a server)");
    ca_sign->add_option("--days", days, "Validity period in days (default: 365)")->check(CLI::Range(1, 3650));
    ca_sign->add_flag("--renew", renew, "Renewal: the current certificate for this subject is replaced");
    ca_sign->add_option("--out", out, "Directory of the kit to hand over to the instance")->required();
    ca_sign->add_option("--passphrase-file", passphrase_file, "Passphrase read from a file");
    auto* ca_list = ca->add_subcommand("list", "Inventory of issued certificates");
    ca_list->add_option("--dir", ca_dir, "CA directory")->required();
    std::string serial, reason = "unspecified";
    int crl_days = 30;
    auto* ca_revoke = ca->add_subcommand("revoke", "Revokes an issued certificate and publishes the CRLs");
    ca_revoke->add_option("--dir", ca_dir, "CA directory")->required();
    ca_revoke->add_option("--serial", serial, "Serial number (ca list)")->required();
    ca_revoke->add_option("--reason", reason, "unspecified, keyCompromise, superseded or cessationOfOperation");
    ca_revoke->add_option("--days", crl_days, "CRL validity in days (default: 30)")->check(CLI::Range(1, 366));
    ca_revoke->add_option("--out", out, "Copy of the CRLs to deploy (crl.pem)");
    ca_revoke->add_option("--passphrase-file", passphrase_file, "Passphrase read from a file");
    auto* ca_crl = ca->add_subcommand("crl", "Publishes the CRLs of the Servers and Clients CAs");
    ca_crl->add_option("--dir", ca_dir, "CA directory")->required();
    ca_crl->add_option("--days", crl_days, "CRL validity in days (default: 30)")->check(CLI::Range(1, 366));
    ca_crl->add_option("--out", out, "Copy of the CRLs to deploy (crl.pem)");
    ca_crl->add_option("--passphrase-file", passphrase_file, "Passphrase read from a file");
    auto* ca_audit = ca->add_subcommand("audit", "CA audit log and integrity check");
    ca_audit->add_option("--dir", ca_dir, "CA directory")->required();
    std::string new_ca_dir;
    auto* ca_root_change = ca->add_subcommand("root-change", "Prepares the root change (trust files, steps)");
    ca_root_change->add_option("--dir", ca_dir, "CA in service (old root)")->required();
    ca_root_change->add_option("--new", new_ca_dir, "New CA (ca init)")->required();
    ca_root_change->add_option("--out", out, "Directory to produce")->required();

    auto* version = app.add_subcommand("version", "Shows the tlsrelay and OpenSSL versions");

    // Commands to a running instance (administration channel).
    Target target;
    auto add_target = [&target](CLI::App* cmd) {
        auto* inst = cmd->add_option("--instance", target.instance, "Instance name (default: default)");
        auto* cfg = cmd->add_option("-c,--config", target.config, "Instance configuration");
        auto* adm = cmd->add_option("--admin", target.admin, "Administration channel endpoint");
        inst->excludes(cfg)->excludes(adm);
        cfg->excludes(adm);
    };
    auto* status = app.add_subcommand("status", "Instance status: PID, uptime, OpenSSL, PKI generation, channels");
    add_target(status);
    auto* channels = app.add_subcommand("channels", "List of open channels");
    add_target(channels);
    auto* metrics = app.add_subcommand("metrics", "Metrics in Prometheus text format");
    add_target(metrics);
    std::string timeout_text;
    auto* stop = app.add_subcommand("stop", "Graceful stop: drain the channels, then stop");
    add_target(stop);
    stop->add_option("--timeout", timeout_text, "Maximum drain duration (default: limits.shutdown_timeout)");
    auto* kill = app.add_subcommand("kill", "Immediate stop, without draining");
    add_target(kill);
    bool kill_old = false;
    auto* reload = app.add_subcommand("reload", "Reloads the whitelist, the PKI and the log levels");
    add_target(reload);
    reload->add_flag("--kill-old", kill_old, "Also closes the connections of retired PKI generations");
    std::string level_spec;
    auto* log_level = app.add_subcommand("log-level", "Changes the log level live");
    add_target(log_level);
    log_level->add_option("level", level_spec, "error|info|debug|trace, or activity=<level>, config=<level>")
        ->required();
    auto* log_reopen = app.add_subcommand("log-reopen", "Reopens the log file (after rotation)");
    add_target(log_reopen);

    // Service manager (systemd, Windows services).
    std::string instance = "default";
    auto* start = app.add_subcommand("start", "Starts the service of an installed instance");
    start->add_option("--instance", instance, "Instance name (default: default)");
    start->add_option("--timeout", timeout_text, "Maximum wait for startup (default: 30s)");
    auto* restart = app.add_subcommand("restart", "Graceful stop then restart of the service");
    restart->add_option("--instance", instance, "Instance name (default: default)");
    restart->add_option("--timeout", timeout_text, "Maximum drain duration");
    auto* service = app.add_subcommand("service", "Installation as a system service");
    service->require_subcommand(1);
    bool boot = false;
    std::string service_config;
    auto* install = service->add_subcommand("install", "Installs the service (systemd tlsrelay@N, Windows tlsrelay-N)");
    install->add_option("--instance", instance, "Instance name (default: default)");
    install->add_option("-c,--config", service_config, "Configuration (default: standard location for the instance)");
    install->add_flag("--boot", boot, "Start automatically with the system");
    auto* uninstall = service->add_subcommand("uninstall", "Stops and uninstalls the service");
    uninstall->add_option("--instance", instance, "Instance name (default: default)");
#ifdef _WIN32
    // Internal command: process launched by the service manager.
    auto* service_run = app.add_subcommand("service-run", "")->group("");
    service_run->add_option("--instance", instance)->required();
    service_run->add_option("-c,--config", config_path)->required();
#endif

    CLI11_PARSE(app, argc, argv);

    if (*check_pki) return cmd_check_pki(config_path, generation);
    if (*activate) return cmd_pki_activate(config_path, generation, force);
    if (*gen_csr) return cmd_gen_csr(config_path, subject, sans);
    if (*pki_crl) return cmd_pki_crl(config_path, crl_file);
    if (*pki_install) {
        auto opt = [](const std::string& v) -> std::optional<std::filesystem::path> {
            return v.empty() ? std::nullopt : std::optional<std::filesystem::path>(v);
        };
        install_files = {opt(from), opt(cert), opt(chain), opt(roots), opt(issuer)};
        return cmd_pki_install(config_path, generation, install_files);
    }
    if (*ca_init) return cmd_ca_init(ca_dir, organization, passphrase_file);
    if (*ca_sign) return cmd_ca_sign(ca_dir, role, csr_path, sans, days, renew, out, passphrase_file);
    if (*ca_list) return cmd_ca_list(ca_dir);
    if (*ca_revoke) return cmd_ca_revoke(ca_dir, serial, reason, crl_days, out, passphrase_file);
    if (*ca_crl) return publish_crl(ca_dir, crl_days, out, passphrase_file);
    if (*ca_audit) return cmd_ca_audit(ca_dir);
    if (*ca_root_change) return cmd_ca_root_change(ca_dir, new_ca_dir, out);

    if (*version) {
        std::cout << "tlsrelay " << tlsrelay::kVersion << '\n'
                  << "library: " << tlsrelay::openssl_runtime_version() << '\n';
        return kExitOk;
    }
    if (*check) return cmd_check_config(config_path);

    if (*status) return send_command(target.endpoint(), "status");
    if (*channels) return send_command(target.endpoint(), "channels");
    if (*metrics) return send_command(target.endpoint(), "metrics");
    if (*reload) return send_command(target.endpoint(), kill_old ? "reload --kill-old" : "reload");
    if (*log_level) return send_command(target.endpoint(), "log-level " + level_spec);
    if (*log_reopen) return send_command(target.endpoint(), "log-reopen");
    if (*stop) return cmd_stop(target, timeout_text);
    if (*kill) return cmd_kill(target);

    auto service_timeout = [&]() -> std::optional<tlsrelay::Duration> {
        if (timeout_text.empty()) return std::chrono::seconds(30);
        return tlsrelay::parse_duration(timeout_text);
    };
    if (*start || *restart) {
        if (!tlsrelay::valid_instance_name(instance)) {
            std::cerr << "error: invalid instance name \"" << instance << "\"\n";
            return kExitConfig;
        }
        const auto timeout = service_timeout();
        if (!timeout) {
            std::cerr << "error: invalid timeout \"" << timeout_text << "\"\n";
            return kExitConfig;
        }
        if (*restart) {
            if (!tlsrelay::app::service_installed(instance)) {
                std::cerr << "error: instance \"" << instance << "\" is not installed as a service\n";
                return kExitRuntime;
            }
            Target t;
            t.instance = instance;
            if (const int code = cmd_stop(t, timeout_text); code != kExitOk) return code;
        }
        return cmd_start(instance, std::chrono::seconds(30));
    }
    if (*install) return cmd_install(instance, service_config, boot);
    if (*uninstall) {
        if (!tlsrelay::valid_instance_name(instance)) {
            std::cerr << "error: invalid instance name \"" << instance << "\"\n";
            return kExitConfig;
        }
        return tlsrelay::app::service_uninstall(instance);
    }
#ifdef _WIN32
    if (*service_run) {
        return tlsrelay::app::service_dispatch(instance, [&](tlsrelay::app::ServiceControl& control) {
            return run_instance(config_path, std::nullopt, instance, &control);
        });
    }
#endif

    std::optional<tlsrelay::LogLevel> level;
    if (quiet) level = tlsrelay::LogLevel::error;
    else if (verbosity == 1) level = tlsrelay::LogLevel::debug;
    else if (verbosity >= 2) level = tlsrelay::LogLevel::trace;
    return run_instance(config_path, level, run_instance_name, nullptr);
}
