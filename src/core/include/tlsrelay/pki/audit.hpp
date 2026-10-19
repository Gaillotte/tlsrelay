#pragma once

// Audit log of the mini-CA (<ca>/audit.log): one line per operation
// (creation, signing, revocation, CRL publication), hash-chained with SHA-256
// so that a modified, deleted or inserted line is detected.
//
// Line format, tab-separated fields:
//   date (UTC)  operator  operation  details  hash
// hash = hexadecimal SHA-256 of "previous hash \t line without
// hash"; the first line starts from 64 zeros.

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tlsrelay::pki {

struct AuditEntry {
    std::string date;
    std::string operator_name;
    std::string operation;  // init, sign, revoke, crl
    std::string details;
};

// Appends an entry. Tabs and line breaks in the fields are replaced
// with spaces. Throws std::runtime_error if writing fails.
void append_audit(const std::filesystem::path& ca_dir, const std::string& operation, const std::string& details);

struct AuditLog {
    std::vector<AuditEntry> entries;  // lines read, up to (excluding) the first chain break
    std::optional<std::size_t> broken_line;  // number (from 1) of the first non-conforming line
    std::string problem;                     // reason for the break
};

// Reads and verifies the log. A missing log is empty and valid (CA created
// before release 1.1).
AuditLog read_audit(const std::filesystem::path& ca_dir);

// System account running the program (operator of the audit entries).
std::string current_operator();

}  // namespace tlsrelay::pki
