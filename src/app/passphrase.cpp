#include "passphrase.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace tlsrelay::app {
namespace {

// Lit une ligne au clavier sans l'afficher.
std::optional<std::string> prompt(const char* text) {
    std::cerr << text << std::flush;
    std::string line;
#ifdef _WIN32
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool console = GetConsoleMode(in, &mode) != 0;
    if (console) SetConsoleMode(in, mode & ~ENABLE_ECHO_INPUT);
    const bool ok = static_cast<bool>(std::getline(std::cin, line));
    if (console) SetConsoleMode(in, mode);
#else
    termios old{};
    const bool tty = ::tcgetattr(STDIN_FILENO, &old) == 0;
    if (tty) {
        termios silent = old;
        silent.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent);
    }
    const bool ok = static_cast<bool>(std::getline(std::cin, line));
    if (tty) ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
#endif
    std::cerr << '\n';
    if (!ok) return std::nullopt;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

}  // namespace

std::optional<std::string> read_passphrase(const std::string& file, bool confirm) {
    if (!file.empty()) {
        std::ifstream in(file, std::ios::binary);
        std::string line;
        if (!in || !std::getline(in, line)) {
            std::cerr << "erreur : phrase de passe illisible dans " << file << '\n';
            return std::nullopt;
        }
        if (!line.empty() && line.back() == '\r') line.pop_back();
        return line;
    }
    if (const char* env = std::getenv("TLSRELAY_CA_PASSPHRASE"); env && *env) return std::string(env);
    auto first = prompt("Phrase de passe de l'AC : ");
    if (!first) return std::nullopt;
    if (confirm) {
        const auto second = prompt("Confirmation : ");
        if (!second || *second != *first) {
            std::cerr << "erreur : les deux saisies diffèrent\n";
            return std::nullopt;
        }
    }
    return first;
}

}  // namespace tlsrelay::app
