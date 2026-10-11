// Canal d'administration sous Windows : named pipe. La première instance du
// pipe sert de verrou (FILE_FLAG_FIRST_PIPE_INSTANCE) ; une instance est
// toujours en attente de connexion tant que le service tourne.

#include "tlsrelay/admin/admin.hpp"
#include "tlsrelay/logging.hpp"

#include "session.hpp"

#include <asio/async_result.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <asio/strand.hpp>
#include <asio/windows/overlapped_ptr.hpp>
#include <asio/windows/stream_handle.hpp>

#include <windows.h>
#include <sddl.h>

#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace tlsrelay::admin {
namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string error_text(DWORD code) { return std::error_code(static_cast<int>(code), std::system_category()).message(); }

// SID du compte qui exécute le processus, au format S-1-5-...
std::wstring current_user_sid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> buffer(size);
    std::wstring result;
    if (size != 0 && GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        LPWSTR text = nullptr;
        if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) {
            result = text;
            LocalFree(text);
        }
    }
    CloseHandle(token);
    return result;
}

// Descripteur de sécurité : SYSTEM, Administrateurs et le compte de l'instance.
class PipeSecurity {
public:
    PipeSecurity() {
        std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
        if (const auto sid = current_user_sid(); !sid.empty()) sddl += L"(A;;GA;;;" + sid + L")";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor_,
                                                                  nullptr)) {
            throw std::runtime_error("canal d'administration : descripteur de sécurité invalide : " +
                                     error_text(GetLastError()));
        }
        attributes_.nLength = sizeof attributes_;
        attributes_.lpSecurityDescriptor = descriptor_;
        attributes_.bInheritHandle = FALSE;
    }
    ~PipeSecurity() {
        if (descriptor_) LocalFree(descriptor_);
    }
    PipeSecurity(const PipeSecurity&) = delete;
    PipeSecurity& operator=(const PipeSecurity&) = delete;

    SECURITY_ATTRIBUTES* attributes() { return &attributes_; }

private:
    PSECURITY_DESCRIPTOR descriptor_ = nullptr;
    SECURITY_ATTRIBUTES attributes_{};
};

constexpr DWORD kBufferSize = 8192;

}  // namespace

struct Server::Impl : std::enable_shared_from_this<Server::Impl> {
    Impl(asio::io_context& io, std::string ep, Handler& h)
        : endpoint(std::move(ep)), wide(widen(endpoint)), handler(h), strand(asio::make_strand(io)) {}

    ~Impl() {
        if (pending != INVALID_HANDLE_VALUE) CloseHandle(pending);
    }

    HANDLE create_instance(bool first) {
        DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if (first) open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        return CreateNamedPipeW(wide.c_str(), open_mode,
                                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                PIPE_UNLIMITED_INSTANCES, kBufferSize, kBufferSize, 0, security.attributes());
    }

    void open() {
        pending = create_instance(true);
        if (pending == INVALID_HANDLE_VALUE) {
            const DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED || err == ERROR_PIPE_BUSY) {
                throw AlreadyRunning("une autre exécution de cette instance est en cours (" + endpoint + ")");
            }
            throw std::runtime_error("canal d'administration : impossible de créer " + endpoint + " : " +
                                     error_text(err));
        }
    }

    // Attend la connexion d'un client sur l'instance du pipe.
    static asio::awaitable<std::error_code> connect(asio::windows::stream_handle& pipe) {
        auto token = asio::as_tuple(asio::use_awaitable);
        auto [ec] = co_await asio::async_initiate<decltype(token)&, void(std::error_code)>(
            [&pipe](auto handler) {
                asio::windows::overlapped_ptr op(
                    pipe.get_executor(),
                    [h = std::move(handler)](std::error_code ec, std::size_t) mutable { std::move(h)(ec); });
                const BOOL ok = ConnectNamedPipe(pipe.native_handle(), op.get());
                const DWORD err = GetLastError();
                if (!ok && err == ERROR_PIPE_CONNECTED) {
                    op.complete(std::error_code(), 0);  // client déjà connecté : pas de notification
                } else if (!ok && err != ERROR_IO_PENDING) {
                    op.complete(std::error_code(static_cast<int>(err), std::system_category()), 0);
                } else {
                    op.release();  // la fin de l'opération sera notifiée par le port de complétion
                }
            },
            token);
        co_return ec;
    }

    asio::awaitable<void> accept_loop() {
        for (;;) {
            if (stopped || pending == INVALID_HANDLE_VALUE) co_return;
            asio::windows::stream_handle pipe(strand, pending);
            pending = INVALID_HANDLE_VALUE;
            current = &pipe;
            const auto ec = co_await connect(pipe);
            current = nullptr;
            if (stopped) co_return;
            // Instance suivante avant de traiter celle-ci : le nom reste toujours réservé.
            pending = create_instance(false);
            if (pending == INVALID_HANDLE_VALUE) {
                logging::config().error("canal d'administration : nouvelle instance de {} impossible : {}", endpoint,
                                        error_text(GetLastError()));
            }
            if (ec) continue;
            ULONG pid = 0;
            std::string caller = "?";
            if (GetNamedPipeClientProcessId(pipe.native_handle(), &pid)) caller = "pid=" + std::to_string(pid);
            // Le handle reste associé au port de complétion : la session garde l'exécuteur de la boucle.
            asio::co_spawn(strand, detail::serve_session(std::move(pipe), handler, std::move(caller)), asio::detached);
        }
    }

    void close() {
        stopped = true;
        if (current) {
            std::error_code ignored;
            current->close(ignored);  // termine l'attente de connexion
        }
        if (pending != INVALID_HANDLE_VALUE) {
            CloseHandle(pending);
            pending = INVALID_HANDLE_VALUE;
        }
    }

    std::string endpoint;
    std::wstring wide;
    Handler& handler;
    asio::strand<asio::io_context::executor_type> strand;
    PipeSecurity security;
    HANDLE pending = INVALID_HANDLE_VALUE;            // instance pas encore attendue (accédé sur strand)
    asio::windows::stream_handle* current = nullptr;  // instance en attente de connexion
    bool stopped = false;
};

Server::Server(asio::io_context& io, std::string endpoint, Handler& handler)
    : impl_(std::make_shared<Impl>(io, std::move(endpoint), handler)) {
    impl_->open();
}

Server::~Server() = default;

void Server::start() {
    asio::co_spawn(impl_->strand, [impl = impl_] { return impl->accept_loop(); }, asio::detached);
}

void Server::stop() {
    asio::post(impl_->strand, [impl = impl_] { impl->close(); });
}

const std::string& Server::endpoint() const { return impl_->endpoint; }

CallResult call(const std::string& endpoint, const std::string& request, Duration timeout) {
    CallResult result;
    const auto name = widen(endpoint);
    const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout.count());
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (;;) {
        pipe = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
                           nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        const DWORD err = GetLastError();
        const ULONGLONG now = GetTickCount64();
        if (err == ERROR_PIPE_BUSY && now < deadline) {
            WaitNamedPipeW(name.c_str(), static_cast<DWORD>(deadline - now));
            continue;
        }
        result.unreachable = err == ERROR_FILE_NOT_FOUND || err == ERROR_PIPE_BUSY;
        result.error = result.unreachable ? "instance injoignable (" + endpoint + ")" : endpoint + " : " + error_text(err);
        return result;
    }

    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    // E/S avec délai : opération asynchrone, attente bornée, annulation si besoin.
    auto io = [&](bool write, void* data, DWORD size, DWORD& done) -> DWORD {
        OVERLAPPED ov{};
        ov.hEvent = event;
        ResetEvent(event);
        const BOOL ok = write ? WriteFile(pipe, data, size, nullptr, &ov) : ReadFile(pipe, data, size, nullptr, &ov);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && err != ERROR_IO_PENDING) return err;
        const ULONGLONG now = GetTickCount64();
        const DWORD wait = now < deadline ? static_cast<DWORD>(deadline - now) : 0;
        if (WaitForSingleObject(event, wait) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            GetOverlappedResult(pipe, &ov, &done, TRUE);
            return WAIT_TIMEOUT;
        }
        if (!GetOverlappedResult(pipe, &ov, &done, FALSE)) return GetLastError();
        return ERROR_SUCCESS;
    };

    std::string line = request + "\n";
    DWORD done = 0;
    DWORD err = io(true, line.data(), static_cast<DWORD>(line.size()), done);
    if (err != ERROR_SUCCESS || done != line.size()) {
        result.error = "envoi impossible : " + (err == WAIT_TIMEOUT ? std::string("délai dépassé") : error_text(err));
    } else {
        std::string data;
        char buffer[4096];
        for (;;) {
            if (auto reply = detail::decode_reply(data, result.error)) {
                result.reply = std::move(reply);
                break;
            }
            if (!result.error.empty()) break;
            err = io(false, buffer, sizeof buffer, done);
            if (err == ERROR_BROKEN_PIPE || (err == ERROR_SUCCESS && done == 0)) {
                result.error = "connexion fermée avant la fin de la réponse";
                break;
            }
            if (err != ERROR_SUCCESS && err != ERROR_MORE_DATA) {
                result.error = err == WAIT_TIMEOUT ? "pas de réponse dans le délai" : error_text(err);
                break;
            }
            data.append(buffer, done);
        }
    }
    CloseHandle(event);
    CloseHandle(pipe);
    return result;
}

}  // namespace tlsrelay::admin
