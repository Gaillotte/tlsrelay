# tlsrelay — Technical specification

> Version 0.1 (phase 0 draft). The development plan is in [`PLAN.md`](PLAN.md).
> Values marked "default" can be changed in the configuration.
> The full list of requirements and how each is verified is in [section 11](#11-requirements).
> Text in `code` that the program prints (log messages, statuses, file names such as `LISEZMOI.txt`) is quoted as the program writes it, in French.

## 1. Vocabulary

| Term | Definition |
|---|---|
| **Application** | Program that connects in plaintext to the client `tlsrelay` |
| **Peer** | A client `tlsrelay` allowed to connect to the server `tlsrelay` (whitelist) |
| **Destination** | Machine (address, port) to which the server `tlsrelay` relays in plaintext |
| **Channel** | One application connection relayed end to end up to the destination |
| **Tunnel session** | State of a channel between the two `tlsrelay` instances, identified by a session id; survives renegotiations |
| **Transport connection** | The TCP connection (and TLS on ports 2 and 3) that carries a tunnel session at a given time |
| **Generation** | Consistent set of key pair + chain + trusted roots, loaded from a versioned PKI directory |
| **Renegotiation** | Replacement of a session's transport connection by a new one, with a full handshake |

## 2. Topology and roles

```
App ──plain TCP──► [client] ══ transport (port 1 plain | port 2 TLS 1.3 | port 3 mTLS) ══► [server] ──plain TCP──► Destination
```

| | Client | Server |
|---|---|---|
| Listens on | 3 local plaintext ports for the application | 3 ports: plain, TLS 1.3, mTLS |
| Connects to | The server `tlsrelay` (one `upstream` per port) | The single destination (3 attempts) |
| Presents a certificate | Port 3: certificate issued by the Clients CA | Ports 2 and 3: certificate issued by the Servers CA |
| Verifies | Server certificate: chain to the root **and** issued by the Servers CA | Port 3: chain to the root, issued by the Clients CA, subject and IP in the whitelist |
| Initiates renegotiation | Yes | No (requires it, and closes the session if it does not happen) |

## 3. TLS parameters

| Parameter | Value |
|---|---|
| Version | TLS 1.3 only (`SSL_CTX_set_min_proto_version` and `max` = `TLS1_3_VERSION`) |
| Cipher suites | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256` (default) |
| Groups | `X25519:P-256:P-384` (default); `X25519MLKEM768` optional with OpenSSL ≥ 3.5 |
| ALPN | `tlsrelay/1`, mandatory; the handshake is refused otherwise |
| SNI | Sent by the client (`server_name` from the configuration); the server certificate's host name is verified |
| Session resumption | Disabled for renegotiations (no ticket presented); ticket keys specific to each `SSL_CTX` |
| mTLS (port 3) | `SSL_VERIFY_PEER \| SSL_VERIFY_FAIL_IF_NO_PEER_CERT` |
| Issuer check | Verification callback: the CA that issued the leaf certificate must be the expected CA (Servers CA on the client side, Clients CA on the server side) |
| Purposes | `X509_PURPOSE_SSL_SERVER` / `X509_PURPOSE_SSL_CLIENT` checked on the whole chain |

## 4. Tunnel protocol `tlsrelay/1`

### 4.1 Frame format

All integers are in network byte order (big-endian).

```
 0       1       2       3       4                               8
 +-------+-------+-------+-------+-------------------------------+
 | type  | flags | reserved (0)  |        length (u32)           |
 +-------+-------+-------+-------+-------------------------------+
 |                  payload (length bytes)                       |
 +---------------------------------------------------------------+
```

- 8-byte header. `length` is the size of the payload alone.
- Maximum payload size: 16 KiB + 64 bytes. Beyond that, the connection is closed with the error `FRAME_TOO_LARGE`.
- An unknown type, a non-zero reserved field or a payload whose size is inconsistent with the type closes the connection (`PROTOCOL_ERROR`).

### 4.2 Frame types

| Code | Frame | Direction | Payload |
|---|---|---|---|
| `0x01` | `OPEN` | C → S | `version` u16 (=1), `session_id` 16 bytes, `port_kind` u8 (1, 2 or 3) |
| `0x02` | `OPEN_OK` | S → C | empty |
| `0x03` | `OPEN_FAIL` | S → C | `code` u16, `message` UTF-8 (≤ 256 bytes) |
| `0x10` | `DATA` | ↔ | `seq` u64, data (≤ 16 KiB) |
| `0x11` | `ACK` | ↔ | `seq` u64: last number received in sequence (cumulative acknowledgement) |
| `0x12` | `SHUTDOWN_WR` | ↔ | `final_seq` u64: no more data in this direction after this number |
| `0x13` | `CLOSE` | ↔ | `code` u16, `message` UTF-8 (≤ 256 bytes) |
| `0x20` | `RESUME` | C → S | `session_id` 16 bytes, `token` 32 bytes, `last_rx_seq` u64 |
| `0x21` | `RESUMED` | S → C | `last_rx_seq` u64 |
| `0x22` | `RESUME_FAIL` | S → C | `code` u16 |
| `0x30` | `PING` | ↔ | `nonce` u64 |
| `0x31` | `PONG` | ↔ | `nonce` u64 |

- `session_id`: 128 bits from `RAND_bytes`, chosen by the client.
- `seq` numbers start at 1 in each direction and are specific to each direction.
- `PING`/`PONG` detect a dead transport that gives no TCP error (silent link); they do **not** push back the idle deadline. Each side sends a `PING` when it has received no frame for `keepalive_interval` (15 s by default); with no frame received for 3 intervals, the transport connection is abandoned: session resumption on ports 2 and 3 (section 4.5), channel closed on port 1. While a delivery is blocked by the application or the destination (back-pressure), that side no longer reads the transport: it gives no verdict, but keeps sending its `PING`s so that the other side does not wrongly conclude that the link is dead.

### 4.3 Opening a channel

1. The application connects to port N of the client.
2. The client opens the transport connection to the `upstream` of port N (TLS handshake on ports 2 and 3), then sends `OPEN`.
3. The server checks the whitelist (section 6), then connects to the destination: up to 3 attempts (section 5.4).
4. On success: `OPEN_OK`. Otherwise: `OPEN_FAIL`, then close.
5. Between `OPEN` and `OPEN_OK`, the client already reads the application's data and buffers it, within the limit of `resume_buffer`.

### 4.4 Transfer and acknowledgements

- Each side keeps the `DATA` frames it sent that are not yet acknowledged, within the limit of `resume_buffer` (4 MiB by default, per direction).
- When the buffer is full, reading from the source (application or destination) is suspended: back-pressure, without loss.
- Received `DATA` frames wait for delivery in a queue: reading the transport connection (and therefore `ACK`, `PING`…) never depends on the speed of the application or the destination. The queue stays within the sender's window (`resume_buffer`, plus one frame).
- An `ACK` acknowledges delivered data (written to the application or the destination). It is sent after 64 KiB delivered or 100 ms without acknowledgement, whichever comes first.
- A `DATA` frame whose `seq` is not exactly the next expected one is a protocol error, except during the replay that follows a resumption (section 4.5), where duplicates already received are ignored.

### 4.5 Transparent renegotiation (ports 2 and 3)

**Resume token**

```
token_n = SSL_export_keying_material(connection_n,
            label   = "EXPORTER-tlsrelay-resume",
            context = session_id || u32(n),
            length  = 32)
```

- `n` is the number of the transport connection within the session (1 for the first).
- Both sides compute the token as soon as connection `n` is established. It is used to resume the session on connection `n+1`; it is single-use.

**Procedure**

1. Deadline: at `session_lifetime × (1 ± session_jitter)` after the current connection was established, the client opens a new transport connection: full handshake, without session resumption, with the **current generation** of certificates and roots.
2. The server applies the same checks as at opening: whitelist (IP + subject + issuing CA). The whitelist entry must be **the same** as for the previous connection.
3. The client sends `RESUME(session_id, token_n, last_rx_seq)`.
4. The server verifies the token (constant-time comparison), marks it as consumed, and replies `RESUMED(last_rx_seq)`.
5. Each side replays, on the new connection, the unacknowledged frames beyond the other side's `last_rx_seq`, then resumes the normal flow. If the other side has already acknowledged more (an `ACK` sent on the old connection after `RESUME`), the replay starts after what it acknowledged.
6. The server closes the old connection cleanly (`close_notify`) as soon as it accepts the resumption.

Throughout the renegotiation, data keeps flowing on the old connection: the application sees neither a pause nor a cut.

**Failures**

- Connection or handshake failure, or no answer to `RESUME` (within `handshake_timeout`): the new connection is closed and the client retries (250 ms wait, doubled at each attempt, 5 s at most) as long as the grace period has not elapsed.
- Refusal by the server — whitelist (the entry must stay the same), invalid or already consumed token, unknown session, inconsistent `last_rx_seq` —: `RESUME_FAIL(code)`. Exception: a session that ended normally (everything received, delivered and acknowledged on its side) is kept for `renegotiation_grace`; a valid resumption then receives `RESUME_FAIL(NORMAL)`, because only the final acknowledgement was lost, and the client closes the channel normally if it has also delivered everything. This refusal is final: the client closes the channel (`CLOSE(NOT_AUTHORIZED)` on the old connection if it is still open).
- The server closes the session (application and destination included), with `CLOSE(LIFETIME_EXCEEDED)`, if no valid `RESUME` has taken place at `session_lifetime × (1 + session_jitter) + renegotiation_grace` after the current connection was established.
- There is never a return to an older transport connection.

**Resumption after a cut** (always active on ports 2 and 3): if the transport connection drops before the deadline, the client applies the same procedure, within `renegotiation_grace`; the server keeps the session (and the connection to the destination) for that same period, then closes it. A cut before `OPEN_OK`, including during the TLS handshake, loses nothing: the client has not yet sent any application data; it reopens the tunnel on a new connection, with a new session (3 attempts at most), then closes the channel if that fails. A refusal during the handshake (certificate) or after it (whitelist on the subject, `OPEN_FAIL`) is not retried. The refusal of an IP address, which closes the connection before the handshake, cannot be told apart from a cut: it is retried like one.

**Port 1**: no `session_lifetime` and no resumption (the token cannot be protected without TLS). Only `idle_timeout` applies.

### 4.6 Closing

- End of one direction: `SHUTDOWN_WR(final_seq)`, then `shutdown(SD_SEND)` towards the application or the destination once all the data has been delivered.
- The channel is closed when both directions are finished and acknowledged, or on `CLOSE`.
- The message of `CLOSE` and `OPEN_FAIL` frames comes from the other tlsrelay and may be logged: its control characters and the backslash are escaped (`\xNN`) when it is decoded.
- Close codes:

| Code | Name | Cause |
|---|---|---|
| 0 | `NORMAL` | Normal end |
| 1 | `IDLE_TIMEOUT` | Inactivity |
| 2 | `LIFETIME_EXCEEDED` | No renegotiation within the grace period |
| 3 | `PEER_REVOKED` | Peer removed from the whitelist, or peer certificate revoked (§7.7) |
| 4 | `DEST_UNREACHABLE` | 3 attempts to the destination failed |
| 5 | `SHUTDOWN` | Service stopping |
| 6 | `PROTOCOL_ERROR` | Invalid frame |
| 7 | `FRAME_TOO_LARGE` | Frame too large |
| 8 | `BUFFER_OVERFLOW` | Resume buffer overflow |
| 9 | `NOT_AUTHORIZED` | Refused by the whitelist |
| 10 | `INTERNAL_ERROR` | Internal error |

## 5. Channels and timers

### 5.1 Channel states

```
            OPEN sent                   OPEN_OK
 OPENING ───────────────► DIALING ─────────────────► ESTABLISHED ◄──────────┐
    │                       │ OPEN_FAIL                 │   │                 │ RESUMED
    │                       ▼                           │   │ deadline /      │
    └──────────────────► CLOSED ◄───────────────────────┘   │ cut             │
                            ▲    CLOSE / timeout /           ▼                 │
                            │    both directions done     MIGRATING ──────────┘
                            └───────────────────────────────┘ grace period exceeded
```

`DIALING` exists only on the server side (connection to the destination); on the client side, the equivalent state is waiting for `OPEN_OK`.

### 5.2 Parameters

| Parameter | Default | Scope |
|---|---|---|
| `idle_timeout` | 5 min | Ports 1, 2, 3; no application data in either direction |
| `session_lifetime` | 1 h | Ports 2, 3 |
| `session_jitter` | 10 % | Ports 2, 3 |
| `renegotiation_grace` | 30 s | Ports 2, 3 |
| `resume_buffer` | 4 MiB | Per direction and per channel |
| `handshake_timeout` | 10 s | Ports 2, 3 |
| `keepalive_interval` | 15 s | All (0: no `PING`) |
| `max_channels` | 5,000 | Per port |

Consistency rules: `idle_timeout` < `session_lifetime`; `renegotiation_grace` < `session_lifetime` / 2; `session_jitter` ≤ 50 %.

### 5.3 Inactivity

The deadline is pushed back by every `DATA` frame (in both directions) and by any data received from the application or the destination. `ACK`, `PING`, `PONG` frames and renegotiation do not push it back.

### 5.4 Connection to the destination

- Up to `dial_retries` attempts (3 by default), each limited by `dial_timeout` (5 s).
- Wait before the next attempt: `dial_backoff` (1 s), doubled at each attempt (1 s, then 2 s).
- After the last failure: `OPEN_FAIL(DEST_UNREACHABLE)` and the `tlsrelay_dial_failures_total` metric.

## 6. Whitelist (server mode)

### 6.1 Format

```yaml
# whitelist.yaml
peers:
  - name: agence-lyon            # unique
    ip: 192.0.2.10               # address or CIDR range, IPv4 or IPv6
    ports: [mtls]                # subset of [plain, tls, mtls]; default: all
    subject: "CN=relay-lyon.example,O=MonEntreprise"   # mandatory for mtls
  - name: labo-test
    ip: 198.51.100.0/28
    ports: [plain, tls]
```

### 6.2 Rules

| Port | Check on TCP accept | Check after the handshake |
|---|---|---|
| 1 (`plain`) | IP in an entry that allows `plain` | — |
| 2 (`tls`) | IP in an entry that allows `tls` | — |
| 3 (`mtls`) | IP in an entry that allows `mtls` (rejected before the handshake otherwise) | Valid chain up to a trusted root, leaf issued by the Clients CA, DN **exactly** equal to the `subject` of an entry that also contains the IP |

- DN comparison: canonical form (`X509_NAME_cmp`), so insensitive to case and to extra spaces, but sensitive to the order of the components. The DN is written in RFC 4514 format, most specific component first; multi-valued names (`+`) and hexadecimal values (`#`) are not accepted.
- `ports` absent: all ports, except `mtls` if the entry has no `subject`.
- File validation: known keys only, unique names, IP/CIDR syntax (host bits zero) and DN syntax, `subject` mandatory if `mtls` is explicitly allowed, the same `subject` cannot appear in two entries. An empty list is accepted with a warning.
- Reloading: the file contents are compared every 2 seconds; any change triggers a reload (`reload` command from phase 6). An invalid file is rejected and the list in force is kept. The `config` log reports the peers added, removed and modified.
- An IPv4 address received on an IPv6 socket (`::ffff:a.b.c.d`) is compared as an IPv4 address.
- Removed peers: their channels are closed immediately (`PEER_REVOKED`); option `revoke_mode: next_renegotiation` to wait for the next renegotiation instead.
- The checks are replayed at every renegotiation.

## 7. PKI

### 7.1 Hierarchy

| Certificate | Key | Validity (default) | Extensions |
|---|---|---|---|
| Root CA | ECDSA P-384 | 15 years | `CA:true`, `keyCertSign`, `cRLSign` |
| Servers CA | ECDSA P-384 | 5 years | `CA:true, pathlen:0`, `keyCertSign`, `cRLSign`, `extendedKeyUsage=serverAuth` |
| Clients CA | ECDSA P-384 | 5 years | `CA:true, pathlen:0`, `keyCertSign`, `cRLSign`, `extendedKeyUsage=clientAuth` |
| Server certificate | ECDSA P-256 | 1 year | `CA:false`, `digitalSignature`, `serverAuth`, DNS and/or IP SAN |
| Client certificate | ECDSA P-256 | 1 year | `CA:false`, `digitalSignature`, `clientAuth` |

### 7.2 PKI directory of an instance

```
<pki_root>/
  ├── v1/
  │   ├── key.pem            # private key (restricted permissions)
  │   ├── cert.pem           # leaf certificate
  │   ├── chain.pem          # intermediate CA that issued the leaf
  │   ├── trust-roots.pem    # one or more trusted roots
  │   └── trust-issuer.pem   # CA(s) expected at the peer (Servers CA on the client side, Clients CA on the server side):
  │                          # one per root, so two during a root change
  ├── v2/ ...
  └── current                # text file containing "v2", replaced by atomic rename
```

- `key.pem`: unencrypted PKCS#8, protected by system permissions (owner only on Linux; SYSTEM and Administrators ACL on Windows). A warning is issued if the permissions are too broad.
- A generation = the full contents of a `vN` directory.

### 7.3 Validating a generation (before switching)

1. All files are present and readable.
2. The key matches the leaf certificate.
3. The chain leaf → `chain.pem` → root verifies against `trust-roots.pem`.
4. CA constraints: `CA:true`, `keyCertSign`, `pathlen`, self-signed root.
5. Valid dates on the whole chain; warning if an expiry occurs in less than `expiry_warning` (30 days).
6. Leaf purpose matches the role (`serverAuth` / `clientAuth`).
7. Rotation guard, compared with the current generation:
   - at least one trusted root in common;
   - the new certificate (if there is one) chains to a trusted root of the current generation.

   Both conditions are always met by the 3-step procedure (§7.5); they refuse a direct jump from one root to another. `trust-roots.pem` is read whenever it is present, even when it is not used to verify a peer (server without an mtls port), so that this check is possible. `pki activate --force` overrides it (emergency).

A failure keeps the current generation and produces an error in the `config` category.

### 7.4 Switching and draining

- Trigger: the contents of `<pki_root>/current` are compared every 2 seconds (if `credentials.watch` is `true`), or explicit reload (`SIGHUP` on Linux; `reload` command from phase 6).
- Each generation maps to one `SSL_CTX` per TLS port. The current contexts are replaced under a lock; each connection keeps a reference to its own.
- A retired generation is released when its last connection closes; the `config` log says so (`génération vN libérée`).
- A refused generation (checks or guard) leaves the current generation in service; the error is logged.
- Since renegotiations use the current generation, a retired generation is released at the latest after `session_lifetime + renegotiation_grace` (ports 2 and 3), or when its channels close (port 1).
- `reload --kill-old`: immediately closes the connections of retired generations (emergency revocation).

### 7.5 Root change

| Step | `trust-roots.pem` | Leaf and `chain.pem` | Condition to move to the next step |
|---|---|---|---|
| 1. Pre-trust | old + new root | old PKI | All `tlsrelay` instances are at step 1 |
| 2. Switch | old + new root | new PKI | All `tlsrelay` instances are at step 2 |
| 3. Withdrawal | new root | new PKI | — |

### 7.6 PKI commands

| Command | Effect |
|---|---|
| `tlsrelay pki gen-csr -c <config> --subject DN [--san ...]` | Creates the next generation `vN`: P-256 key (`key.pem`, readable by the owner only) and `request.csr`. The SANs in it are only indicative. Activates nothing |
| `tlsrelay pki install -c <config> [--generation vN] [--from kit] [--cert] [--chain] [--roots] [--issuer]` | Completes the pending request (or `vN`); missing trust files are taken from the current generation; checks of section 7.3, guard included. Activates nothing. Instance without an identity (TLS client): creates a trust-only generation |
| `tlsrelay check-pki -c <config> [vN]` | Applies the validation of section 7.3, guard included, without switching (default: current generation) |
| `tlsrelay pki activate -c <config> <vN> [--force]` | Checks like `check-pki`, then updates `current` (atomic rename) |
| `tlsrelay ca init --dir <ca> [--org O]` | Creates the root and the two intermediate CAs (section 7.1); refuses a non-empty directory |
| `tlsrelay ca sign --dir <ca> --role server\|client --csr <file> [--san ...] [--days 365] [--renew] --out <kit>` | Signs a request and writes the kit `cert.pem`, `chain.pem`, `trust-roots.pem`, `trust-issuer.pem` for `pki install --from` |
| `tlsrelay ca list --dir <ca>` | Inventory: serial, role, status (`valide` valid, `remplacé` superseded, `révoqué` revoked), end of validity, subject, revocation date and reason |
| `tlsrelay ca revoke --dir <ca> --serial S [--reason reason] [--days 30] [--out crl.pem]` | Revokes an issued certificate (RFC 5280 reasons: `unspecified`, `keyCompromise`, `superseded`, `cessationOfOperation`) then publishes the CRLs (§7.7) |
| `tlsrelay ca crl --dir <ca> [--days 30] [--out crl.pem]` | Publishes the CRLs of the Servers and Clients CAs (to be redone before they expire) |
| `tlsrelay ca audit --dir <ca>` | Shows the CA's audit log and verifies its hash chain |
| `tlsrelay ca root-change --dir <old> --new <new> --out <directory>` | Prepares the root change (§7.5): trust files for steps 1 and 2 per role (`serveur/`, `client/`: two roots, expected CA of both roots), CRLs of both CAs, `LISEZMOI.txt` with the commands for each step |
| `tlsrelay pki crl -c <config> <file>` | Checks the CRLs against the current generation, then installs them in `<pki_root>/crl.pem` (atomic rename) |

**`ca sign` policy**

- The request's signature is verified (proof of possession of the key); the key must be ECDSA P-256; the subject must contain a CN.
- Requested extensions are ignored (and listed): the certificate receives `CA:false`, `digitalSignature`, the role's purpose (`serverAuth` or `clientAuth`), SKI, AKI, and the SANs given by the operator (`--san`, mandatory for a server).
- A subject already assigned to a currently valid certificate is refused, except with `--renew` (same role): the old certificate is then marked `remplacé` (superseded).
- End of validity: `--days` (365 by default), never beyond that of the signing CA. Random 128-bit serial number; SHA-384 signature.

**CA directory**: `root.*`, `servers.*`, `clients.*` (`.key.pem` and `.cert.pem`), `index.tsv` (inventory), `issued/<serial>.pem`, `crl.pem` and `crlnumber` (last published CRLs), `audit.log` (audit log). CA keys: PKCS#8 encrypted with AES-256-CBC, scrypt derivation (N = 2¹⁴, r = 8, p = 1); passphrase of at least 12 characters, typed without echo, or read from `--passphrase-file` or `TLSRELAY_CA_PASSPHRASE`. Permissions: `0600` on Linux; protected ACL (SYSTEM, Administrators, operator account) on Windows.

**Instance key on Windows**: `key.pem` inherits the permissions of the `pki_root` directory, which must be reserved for Administrators and the service account (for example `icacls <pki_root> /inheritance:r /grant:r "Administrators:(OI)(CI)F" "NT SERVICE\tlsrelay-N:(OI)(CI)R"`; use the localised name of the Administrators group).

**Audit log** (`<ca>/audit.log`): one line per operation (`init`, `sign`, `revoke`, `crl`, `root-transition`), tab-separated fields: UTC date, operator account, operation, details, hash. The hash is the SHA-256 of "previous hash, tab, line without its hash" (64 zeros for the first line): a modified, deleted or inserted line breaks the chain, which `ca audit` reports. A CA directory created before delivery 1.1 gets its log at the first operation.

The graphical inventory and the renewal and root-change wizards belong to the `tlsrelay-admin` editor (delivery 1.1).

### 7.7 Revocation (CRL)

- **Publication**: `ca revoke` or `ca crl` produce one v2 CRL per intermediate CA (Servers CA, Clients CA), signed with SHA-384, with an increasing CRL number, the CA's key identifier and the revocation reason; valid 30 days by default (`--days`, never beyond the CA's own validity). Both CRLs are written to a single file, to be deployed on all instances.
- **Deployment**: `<pki_root>/crl.pem` of each instance (`tlsrelay pki crl -c <config> <file>`, or a copy followed by a rename). The file is shared by all generations.
- **Check on load**: only the CRLs of the CAs expected at the peer (`trust-issuer.pem`) count; their signature is verified with the CA's key. A CRL in the name of an expected CA but with an invalid signature makes the file be refused. CRLs of other CAs are ignored, except to report that the instance's own certificate is revoked. Warnings: expected CA without a CRL (its certificates are not checked), stale CRL (next-update date passed: it is still applied, it must be republished), CRL dated in the future.
- **Enforcement**: at the handshake, a peer certificate listed in its issuer's CRL is refused (TLS alert; reason `certificat du client révoqué` or `certificat du serveur révoqué` in the log); the server does not contact the destination. The check covers the peer's certificate, not the intermediate CAs.
- **Reloading**: the contents of `crl.pem` are compared every 2 seconds (if `credentials.watch` is `true`), and reread by `reload` and at every generation switch. An invalid file keeps the CRLs in force (error in the `config` category, counter `tlsrelay_crl_reload_failures_total`); at startup, it prevents the service from starting. A deleted file disables the check (warning).
- **Open channels**: when a CRL adds revoked certificates, the channels whose peer presents one of them are closed (code `PEER_REVOKED`, reason `certificat_revoque`, counter `tlsrelay_certificates_revoked_total`), except with `revoke_mode: next_renegotiation` (server): they are then refused at their next renegotiation.
- **Instances concerned**: those that verify their peer's certificate: server with an `mtls` port, client with a `tls` or `mtls` port. `status` shows the number of revoked certificates and the next update; metric `tlsrelay_crl_revoked_certificates`.

## 8. Configuration

### 8.1 Client mode

```yaml
mode: client
instance: rc-client
logging:
  level: info
  categories: { activity: info, config: info }
  format: text                 # text | json
  output: stderr               # stderr | <path> | syslog | eventlog
credentials:
  pki_root: /etc/tlsrelay/rc-client/pki
  watch: true
  expiry_warning: 30d
limits:
  idle_timeout: 5m
  session_lifetime: 1h
  session_jitter: 10%
  renegotiation_grace: 30s
  resume_buffer: 4MiB
  handshake_timeout: 10s
  keepalive_interval: 15s
  max_channels: 5000
  shutdown_timeout: 30s
ports:
  plain: { listen: "127.0.0.1:7001", upstream: "relay.example:9001" }
  tls:   { listen: "127.0.0.1:7002", upstream: "relay.example:9002", server_name: relay.example }
  mtls:  { listen: "127.0.0.1:7003", upstream: "relay.example:9003", server_name: relay.example }
source_address: 0.0.0.0        # source address of the connections to the server (optional)
```

### 8.2 Server mode

```yaml
mode: server
instance: rc-server
destination:
  address: 10.0.0.42
  port: 8080
  dial_timeout: 5s
  dial_retries: 3
  dial_backoff: 1s
whitelist:
  file: /etc/tlsrelay/rc-server/whitelist.yaml
  revoke_mode: immediate       # immediate | next_renegotiation
credentials: { pki_root: /etc/tlsrelay/rc-server/pki, watch: true }
limits: { ... }                # same as client mode
ports:
  plain: { listen: "0.0.0.0:9001" }
  tls:   { listen: "0.0.0.0:9002" }
  mtls:  { listen: "0.0.0.0:9003" }
```

A port absent from the configuration is not opened.

Section common to both modes (optional):

```yaml
admin:
  enabled: true                  # administration channel (§10.1)
  endpoint: /run/tlsrelay/rc-server.sock   # default depends on the system and the instance
```

### 8.3 Validation rules (shared with the editor)

- `mode` ∈ {client, server}; `destination` mandatory in server mode, forbidden in client mode; `upstream` mandatory for each port in client mode.
- Ports in 1–65535, no duplicate listen address.
- Durations and sizes in the `<number><unit>` format; consistency rules of section 5.2.
- `pki_root` mandatory if `tls` or `mtls` is configured; valid current generation (section 7.3).
- `whitelist.file` mandatory in server mode; valid file (section 6.2).
- Log levels ∈ {error, info, debug, trace}.

## 9. Logging

| Level | Contents |
|---|---|
| `error` | Errors |
| `info` | Startup, shutdown, reloads, whitelist rejections, failures towards the destination, **all configuration operations** |
| `debug` | Opening and closing of each channel, renegotiations, generations retired and released |
| `trace` | Handshake details (version, suite, chain presented), frames (type, `seq`, size), connection attempts |

- Context fields: `instance`, `channel_id`, `session_id` (truncated), `generation`, `peer`, `port`.
- Never logged: private keys, tokens, derived secrets, contents of the relayed data.
- Data coming from a peer (certificate subject, `CLOSE` message): control characters escaped; one log line can never become several.
- Runtime change: `tlsrelay log-level <level>` or `tlsrelay log-level <category>=<level>`.
- `tlsrelay log-reopen` (and `SIGUSR1` on Linux) reopens the log file.

## 10. Command line and lifecycle

| Command | Effect |
|---|---|
| `tlsrelay run -c <config> [--instance N] [-v\|-vv\|-q]` | Runs in the console (Ctrl+C: graceful stop; second Ctrl+C: immediate stop). `--instance` checks that the configuration is that of instance N |
| `tlsrelay service install [--instance N] [-c <config>] [--boot]` | Installs the service (systemd `tlsrelay@N`, Windows service `tlsrelay-N`); `--boot`: start with the system |
| `tlsrelay service uninstall [--instance N]` | Stops (with drain) and uninstalls |
| `tlsrelay start\|restart [--instance N] [--timeout 30s]` | Starts the installed service (waits until the administration channel answers); restart = graceful stop then start |
| `tlsrelay stop [target] [--timeout duration]` | Graceful stop: no new connection accepted, channels drained, then stop; waits for the process to end |
| `tlsrelay kill [target]` | Immediate stop; if the channel no longer answers, forced stop by the service manager |
| `tlsrelay reload [target] [--kill-old]` | Reloads the whitelist, the PKI and the log levels, without stopping; shows the outcome |
| `tlsrelay status [target]` | State, PID, uptime, OpenSSL version, current and draining generations, channels per port |
| `tlsrelay channels [target]` | Open channels: port, state, session, peer, generation, connection number, age, idle time, bytes |
| `tlsrelay metrics [target]` | Metrics in Prometheus text format |
| `tlsrelay log-level [target] <level\|category=level>` | Log level at runtime |
| `tlsrelay log-reopen [target]` | Reopens the log file (rotation); also `SIGUSR1` on Linux |
| `tlsrelay check-config -c <config>` | Validates a configuration without loading it |

`target`: `--instance N` (default `default`), `-c <config>` (instance and endpoint read from the configuration) or `--admin <endpoint>`.

### 10.1 Administration channel

- Endpoint: Unix socket `/run/tlsrelay/<instance>.sock` (permissions `0660`, group `tlsrelay` if it exists, directory `0750`); named pipe `\\.\pipe\tlsrelay-<instance>` (Administrators, SYSTEM and the instance's account; remote clients refused). Configurable: `admin.endpoint`; can be disabled: `admin.enabled: false`.
- In the console, if the default location is not accessible (user without rights on `/run/tlsrelay`), the relay starts without a channel, with a warning.
- Protocol: one command per connection. Request: one line of text (4 KiB at most, 5 s to send it). Response: `OK <n>` or `ERREUR <n>` (error), then `n` bytes of UTF-8 text.
- Each command is logged with the caller's identity (uid and pid on Linux, pid on Windows): `info` level for commands that change the state, `debug` for queries.
- Instance lock: `flock` on `<endpoint>.lock` on Linux, first instance of the named pipe on Windows. A second execution of the same instance is refused; a socket left behind by an abrupt stop is replaced.

### 10.2 Reload

- Whitelist and PKI: as with `SIGHUP` (sections 6 and 7.4).
- Configuration: the file is reread; only the log levels apply at runtime. Other modified sections (ports, destination, limits, etc.) are reported: they require a restart.

### 10.3 Services

- **Linux (systemd)**: template unit `/etc/systemd/system/tlsrelay@.service` and per-instance drop-in (`tlsrelay@N.service.d/10-tlsrelay.conf`: configuration, stop timeout = `shutdown_timeout` + 15 s). `Type=notify` (ready when the ports are open), system account `tlsrelay`, `ProtectSystem=strict`, `ProtectHome`, only capability `CAP_NET_BIND_SERVICE`, restart on failure. Default configuration: `/etc/tlsrelay/<instance>.yaml`. The binary must be installed outside `/home`.
- **Windows**: service `tlsrelay-N` running under the virtual account `NT SERVICE\tlsrelay-N` (only privilege: `SeChangeNotifyPrivilege`), system shutdown notified (`PRESHUTDOWN`) with the drain delay, restart on failure. Default configuration: `%ProgramData%\tlsrelay\<instance>.yaml`; if `logging.output` is `stderr`, the log goes to `%ProgramData%\tlsrelay\logs\<instance>.log`. An unreadable or invalid configuration at service start is also recorded there (the service has no console).
- The service account must be able to read the configuration, the whitelist and the PKI; these files must be readable only by it and by administrators.
- Listening sockets: `SO_REUSEADDR` (Linux), `SO_EXCLUSIVEADDRUSE` (Windows).
- At startup: check of the loaded OpenSSL version (≥ 3.0), written to the logs.

### 10.4 Metrics

Prometheus text format (version 0.0.4), read by `tlsrelay metrics` over the administration channel: no additional network port is opened. An exporter (for example node_exporter's textfile collector) can write it periodically to a file. All series carry the `instance` label.

| Series | Type |
|---|---|
| `tlsrelay_info{mode,version,openssl}` | gauge (1) |
| `tlsrelay_process_resident_memory_bytes`, `tlsrelay_process_open_descriptors` (handles on Windows) | gauge |
| `tlsrelay_uptime_seconds` | gauge |
| `tlsrelay_channels_active{port}` | gauge |
| `tlsrelay_pki_generation_info{generation}`, `tlsrelay_pki_generations_live` | gauge |
| `tlsrelay_crl_revoked_certificates` (instances that verify their peer) | gauge |
| `tlsrelay_channels_{opened,closed,rejected,idle_closed}_total` | counter |
| `tlsrelay_dial_attempt_failures_total`, `tlsrelay_dial_failures_total` | counter |
| `tlsrelay_tls_handshake_failures_total`, `tlsrelay_peers_{rejected,revoked}_total` | counter |
| `tlsrelay_pki_rotations_total`, `tlsrelay_pki_reload_failures_total` | counter |
| `tlsrelay_certificates_revoked_total`, `tlsrelay_crl_reload_failures_total` | counter |
| `tlsrelay_renegotiations_total`, `tlsrelay_resume_failures_total`, `tlsrelay_protocol_errors_total` | counter |
| `tlsrelay_bytes_{upstream,downstream}_total` (closed channels) | counter |

## 11. Requirements

Full list of the solution's requirements, deliveries 1.0 (service) and 1.1 (editor), with how each is verified. A requirement is met when all its verifications pass (PLAN §5.1). Test names refer to the GoogleTest suites (`tests/`) and Qt Test cases (`tests/admin/`); scripts are in `tests/lifecycle/`, `tests/perf/` and `tools/`; R01 to R13, M01 to M09 and E01 to E10 are the acceptance-test scenarios ([RECETTE.md](RECETTE.md)).

### 11.1 General and platforms

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| GEN-01 | Runs on Windows 10, 11 and Server 2019 or later (64-bit) and on Linux: Ubuntu 22.04 and 24.04, Debian 12, RHEL 9 and equivalents | PLAN §2 | 1.0 | CI: Windows MSVC, Linux GCC and Clang; packages installed on Ubuntu 22.04 and 24.04, Debian 12, Rocky 9, Alma 9; R13 (cross tests) |
| GEN-02 | OpenSSL 3.0 or later, dynamically linked; OpenSSL 3.5 LTS shipped on Windows; version checked and logged at startup | §10.3 | 1.0 | Job "Linux OpenSSL 3.5 LTS"; Windows CI step "Version d'OpenSSL embarquée"; R02 |
| GEN-03 | Works as a pair: one client tlsrelay and one server tlsrelay; the peer is always a tlsrelay (tunnel protocol and ALPN mandatory) | §2, §3 | 1.0 | `TlsTest.ServerRejectsMissingAlpn`, `AttackTest.ClientSendsNothingToValidFakeServerWithoutTunnelProtocol` |
| GEN-04 | Three ports per instance: `plain` (plaintext), `tls` (TLS 1.3), `mtls` (mutual TLS 1.3); a port absent from the configuration is not opened | §2, §8 | 1.0 | `Relay.PlainChainPreservesDataIntegrity`, `TlsTest.ChainPreservesDataIntegrity`, `MtlsTest.ChainPreservesDataIntegrity`, R03 |
| GEN-05 | Server mode: plaintext output to a single destination (configurable address and port); client mode: plaintext input from the application | §2, §8 | 1.0 | `Relay.*`, R03 |

### 11.2 TLS

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| TLS-01 | TLS 1.3 only on the `tls` and `mtls` ports: TLS 1.2 and plaintext are refused | §3 | 1.0 | `TlsTest.ServerRejectsTls12`, `TlsTest.ServerRejectsPlaintextOnTlsPort`, `tests/lifecycle/tls-scan.sh` (sslyze, testssl.sh) |
| TLS-02 | Only the cipher suites and groups of section 3 | §3 | 1.0 | `tls-scan.sh` |
| TLS-03 | ALPN `tlsrelay/1` mandatory | §3 | 1.0 | `TlsTest.ServerNegotiatesTls13WithAlpn`, `TlsTest.ServerRejectsMissingAlpn`, `TlsTest.ServerRejectsWrongAlpn` |
| TLS-04 | No TLS session resumption: full handshake on every transport connection | §3 | 1.0 | `tls-scan.sh` |
| TLS-05 | The client verifies the server's chain up to a trusted root, the expected name or IP address, and the issuing CA (Servers CA) | §3 | 1.0 | `TlsTest.ClientRejectsServerFromAnotherPki`, `TlsTest.ClientRejectsWrongServerName`, `TlsTest.ClientAcceptsIpAddressAsServerName`, `TlsTest.ClientRejectsServerCertificateFromUnexpectedCa`, `AttackTest.ClientRejectsServerPresentingClientCertificate` |
| TLS-06 | On the `mtls` port the server requires a client certificate issued by the Clients CA, with the `clientAuth` purpose | §3 | 1.0 | `MtlsTest.ServerRejectsClientWithoutCertificate`, `MtlsTest.ServerRejectsClientCertificateFromUnexpectedCa`, `MtlsTest.ServerRejectsServerCertificateUsedAsClientCertificate` |
| TLS-07 | Expired or not-yet-valid certificates refused, on both sides | §3, §7.3 | 1.0 | `AttackTest.ClientRejectsExpiredServerCertificate`, `AttackTest.ClientRejectsNotYetValidServerCertificate`, `AttackTest.ServerRejectsExpiredClientCertificate`, `AttackTest.ServerRejectsNotYetValidClientCertificate` |
| TLS-08 | A connection that does not complete its handshake within `handshake_timeout` is closed; a flood of silent connections stays bounded | §5.2 | 1.0 | `TlsTest.HandshakeTimeoutClosesSilentConnection`, `AttackTest.ConnectionFloodWithoutHandshakeIsBoundedAndRecovers` |

### 11.3 Tunnel protocol

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| TUN-01 | Frames as in 4.1 and 4.2; unknown frame, non-zero reserved field, inconsistent size or size above 16 KiB + 64 bytes: close | §4.1, §4.2 | 1.0 | `Frame.*`, `TunnelTest.InvalidFrameClosesChannelWithProtocolError`, `AttackTest.OversizedFrameHeaderClosesChannelBeforePayload`, fuzzing `fuzz_frame` |
| TUN-02 | Opening with `OPEN` / `OPEN_OK` / `OPEN_FAIL`; application data read before `OPEN_OK` is buffered | §4.3 | 1.0 | `TunnelTest.OpenIsRefusedForAnotherPortOrDuplicateSession`, `AttackTest.DataBeforeOpenIsRefused` |
| TUN-03 | `DATA` numbered per direction, cumulative acknowledgements; an out-of-sequence `DATA` is a protocol error | §4.4 | 1.0 | `AttackTest.DataWithUnexpectedSequenceClosesChannel` |
| TUN-04 | Back-pressure without loss, within `resume_buffer` per direction and per channel | §4.4 | 1.0 | `TunnelTest.SmallResumeBufferAppliesBackpressureWithoutLoss` |
| TUN-05 | Reading the transport connection does not depend on the speed of the application or the destination | §4.4 | 1.0 | `TunnelTest.SlowDestinationDoesNotStallAcknowledgements`, `TunnelTest.KeepaliveToleratesApplicationNotReading` |
| TUN-06 | Transparent renegotiation at `session_lifetime × (1 ± session_jitter)`: new connection, full handshake with the current PKI generation, without a cut or loss | §4.5 | 1.0 | `TunnelTest.RenegotiationIsTransparentUnderLoad`, `TunnelTest.RenegotiationMovesOpenChannelToNewGeneration`, R07 |
| TUN-07 | Resumption with a token derived from the TLS exporter of the previous connection, single-use, compared in constant time; same whitelist entry required | §4.5 | 1.0 | `TunnelTest.ResumeTokenIsBoundToConnectionAndSingleUse` |
| TUN-08 | The server closes a session that is not renegotiated within the grace period (`LIFETIME_EXCEEDED`) | §4.5 | 1.0 | `TunnelTest.ServerClosesSessionThatIsNotRenegotiated` |
| TUN-09 | Session resumption after a cut, within `renegotiation_grace`, without loss or duplication | §4.5 | 1.0 | `TunnelTest.SessionResumesAfterTransportLoss`, `TunnelTest.ServerWaitsForResumeOnlyDuringGrace`, R06 |
| TUN-10 | Cut before `OPEN_OK`, including during the handshake: tunnel reopened on a new connection, without loss | §4.5 | 1.0 | `TunnelTest.TransportLossBeforeOpenOkReopensTunnel`, `TunnelTest.TransportLossDuringHandshakeReopensTunnel` |
| TUN-11 | `PING` / `PONG`: a silent link is detected after 3 `keepalive_interval`s; resumption on the `tls` and `mtls` ports, close on the `plain` port | §4.2 | 1.0 | `TunnelTest.SilentTransportIsDetectedByKeepaliveAndResumed`, `TunnelTest.SilentPlainTransportClosesChannel` |
| TUN-12 | `plain` port: no lifetime and no resumption; a cut closes the channel | §4.5 | 1.0 | `TunnelTest.PlainTransportLossClosesChannel` |
| TUN-13 | Half-close propagated end to end, the other direction continuing | §4.6 | 1.0 | `Relay.HalfClosePropagatesThroughTheChain`, `TlsTest.HalfClosePropagatesOverTls` |
| TUN-14 | `CLOSE` and `OPEN_FAIL` messages from the peer truncated and escaped | §4.6 | 1.0 | `Frame.StatusMessageControlCharactersAreEscaped`, `Frame.StatusMessageIsTruncated`, `AttackTest.PeerMessageCannotInjectLogLines` |

### 11.4 Channels and timers

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| CAN-01 | Several channels in parallel per port, one tunnel session per channel | §5 | 1.0 | `Relay.ManyChannelsInParallel`, `TlsTest.ManyChannelsInParallel`, R03 |
| CAN-02 | `max_channels` per port: extra connections are refused | §5.2 | 1.0 | `Relay.MaxChannelsRejectsExtraConnections` |
| CAN-03 | `idle_timeout` on all three ports; only application data pushes the deadline back | §5.3 | 1.0 | `Relay.IdleTimeoutClosesChannel`, `Relay.ActivityKeepsChannelOpen` |
| CAN-04 | Connection to the destination: `dial_retries` attempts (3 by default) limited by `dial_timeout`, wait doubled; then `OPEN_FAIL(DEST_UNREACHABLE)` | §5.4 | 1.0 | `Relay.DestinationRetrySucceeds`, `Relay.DestinationUnreachableAfterThreeAttempts` |
| CAN-05 | Timer consistency: `idle_timeout` < `session_lifetime`, `renegotiation_grace` < `session_lifetime` / 2, `session_jitter` ≤ 50 % | §5.2 | 1.0 | `Validate.LimitsCoherence` |

### 11.5 Whitelist

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| WL-01 | File strictly validated: known keys, unique names and subjects, IP or CIDR, DN; empty list accepted with a warning | §6.1, §6.2 | 1.0 | `Whitelist.*`, fuzzing `fuzz_whitelist` and `fuzz_dn` |
| WL-02 | Address checked on TCP accept, before any handshake, for the requested port | §6.2 | 1.0 | `MtlsTest.UnknownAddressIsRejectedBeforeHandshake`, `MtlsTest.PeerIsLimitedToItsPorts`, `Whitelist.AuthorizesByIpAndPort` |
| WL-03 | `mtls` port: certificate subject and address in the same entry; canonical DN comparison | §6.2 | 1.0 | `MtlsTest.WhitelistRequiresIpAndSubjectInTheSameEntry`, `MtlsTest.WhitelistRejectsUnknownSubjectBeforeContactingDestination`, `Dn.ParsesEscapesAndMatchesCertificateForm` |
| WL-04 | Hot reload (2 s watch, `reload`); invalid file refused, list in force kept; additions, removals and changes logged | §6.2 | 1.0 | `MtlsTest.ReloadAddsPeer`, `MtlsTest.InvalidReloadKeepsCurrentList`, `Whitelist.DiffReportsChanges`, R05 |
| WL-05 | Removed peer: its channels are closed (`PEER_REVOKED`), or refused at the next renegotiation with `revoke_mode: next_renegotiation` | §6.2 | 1.0 | `MtlsTest.ReloadRevokesActiveChannelOfRemovedPeer`, `MtlsTest.ReloadWithNextRenegotiationKeepsActiveChannel` |
| WL-06 | Invalid whitelist at startup: the service does not start | §6.2 | 1.0 | `MtlsTest.ServiceRefusesInvalidWhitelistAtStartup` |

### 11.6 Instance PKI

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| PKI-01 | Hierarchy: P-384 root, Servers CA and Clients CA (`pathlen:0`, role purpose), P-256 instance certificates | §7.1 | 1.0 | `CaTest.InitCreatesHierarchyWithEncryptedKeys`, `CaTest.ProvisionedPkiCarriesAnMtlsChain`, `pki.sh` (`openssl verify`) |
| PKI-02 | Versioned generations; `current` replaced by atomic rename | §7.2 | 1.0 | `PkiTest.ActivateReplacesCurrentPointer`, `PkiTest.RejectsMissingOrInvalidPointer` |
| PKI-03 | Full validation of a generation before switching: files, key and certificate, chain, CA constraints, dates, role purpose; expiry warning | §7.3 | 1.0 | `PkiTest.*` |
| PKI-04 | Instance key generated on the machine, never encrypted nor prompted for, readable by the owner only | §7.2, §7.6 | 1.0 | `PkiTest.RejectsEncryptedKeyWithoutPrompting`, `CaTest.GenCsrCreatesNextGenerationWithPrivateKey` |
| PKI-05 | Hot rotation of the key pair, the certificate and the CAs: new connections on the new generation, old ones draining, generation released at its last connection; `reload --kill-old` | §7.4 | 1.0 | `RotationTest.NewConnectionsUseNewGenerationWhileOldOnesDrain`, `RotationTest.OldGenerationIsReleasedWhenItsLastConnectionCloses`, `RotationTest.KillOldClosesConnectionsOfRetiredGeneration`, R08 |
| PKI-06 | Invalid generation refused, service kept running; invalid PKI at startup: the service does not start | §7.3, §7.4 | 1.0 | `RotationTest.InvalidGenerationIsRefusedAndServiceContinues`, `TlsTest.ServiceRefusesToStartWithInvalidPki` |
| PKI-07 | Rotation guard: common root and chaining to a known root of the current generation; `pki activate --force` for emergencies | §7.3 | 1.0 | `PkiTest.CheckCandidateAppliesRootGuard`, `RotationTest.GuardRefusesRootChangeWithoutPreTrust`, `RotationTest.GuardRefusesIdentityFromUnknownRootEvenWithoutMtls` |
| PKI-08 | Three-step root change, without interruption | §7.5 | 1.0 | `RotationTest.ThreeStepRootChangeKeepsServiceAvailable`, `CaTest.RootTransitionFilesDriveTheThreeSteps`, R09 |
| PKI-09 | Pick-up: watch on `current` (2 s, can be disabled), `SIGHUP`, `reload` | §7.4 | 1.0 | `RotationTest.SighupTriggersReload`, `RotationTest.WatchDisabledWaitsForExplicitReload` |
| PKI-10 | Instance commands `pki gen-csr`, `pki install` (checks and guard), `pki activate`, `check-pki` | §7.6 | 1.0 | `CaTest.InstallRejectsCertificateForAnotherKey`, `CaTest.RenewalRotatesKeyAndKeepsTrustFiles`, `pki.sh`, `windows-pki.ps1`, R01 |

### 11.7 Mini-CA

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| CA-01 | `ca init`: encrypted CA keys (scrypt, AES-256-CBC), passphrase of at least 12 characters, restricted permissions (0600, protected ACL); non-empty directory refused | §7.6 | 1.0 | `CaTest.InitCreatesHierarchyWithEncryptedKeys`, `windows-pki.ps1` (ACL) |
| CA-02 | Signing policy: proof of possession, P-256 key, CN, extensions set by the CA, SAN mandatory for a server, validity bounded by the CA | §7.6 | 1.0 | `CaTest.SignAppliesCaPolicyAndIgnoresRequestedExtensions`, `CaTest.SignRefusesNonConformingRequests`, fuzzing `fuzz_csr` |
| CA-03 | A subject is assigned only once, except on renewal; the old certificate is then marked superseded | §7.6 | 1.0 | `CaTest.SubjectIsAttributedOnceUnlessRenewed` |
| CA-04 | Inventory of issued certificates (`ca list`), including inventories from before delivery 1.1 | §7.6 | 1.0 | `CaTest.IndexWithoutRevocationColumnsIsStillRead`, `CaTest.DescribeAuthoritySummarizesCertificatesAndCrl` |
| CA-05 | Revocation (`ca revoke`, RFC 5280 reason) and publication of signed, numbered v2 CRLs, one per intermediate CA (`ca crl`) | §7.6, §7.7 | 1.1 | `CaTest.RevocationIsPublishedInSignedCrls`, `pki.sh` (`openssl verify -crl_check`) |
| CA-06 | Audit log of CA operations, hash-chained with SHA-256; tampering is detected (`ca audit`) | §7.6 | 1.1 | `CaTest.AuditLogRecordsOperationsAndDetectsTampering`, `pki.sh`, `windows-pki.ps1` |
| CA-07 | Root-change preparation: trust files per role, CRLs of both CAs, commands (`ca root-change`) | §7.6 | 1.1 | `CaTest.RootTransitionFilesDriveTheThreeSteps`, R09 |

### 11.8 Revocation enforced by the service

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| CRL-01 | CRLs from `<pki_root>/crl.pem` verified (signature of the expected CA); revoked certificate refused at the handshake, on the server side as on the client side | §7.7 | 1.1 | `CrlTest.ServerRefusesRevokedClientCertificate`, `CrlTest.ClientRefusesRevokedServerCertificate`, `CrlTest.CrlOfOtherCertificatesChangesNothing`, `CaTest.PublishedCrlIsAcceptedByInstancesOfBothRoles` |
| CRL-02 | CRLs reloaded at runtime (watch, `reload`, generation switch); channels of a revoked peer closed, except with `next_renegotiation` | §7.7 | 1.1 | `CrlTest.PublishedCrlClosesActiveChannelAndRefusesNewOnes`, `CrlTest.NextRenegotiationKeepsActiveChannel` |
| CRL-03 | Invalid CRL: refusal to start, then CRLs in force kept; stale CRL applied with a warning; revoked instance certificate reported | §7.7 | 1.1 | `CrlTest.InvalidCrlIsRefusedAtStartupAndKeptAsIsOnReload`, `CrlTest.ExpiredCrlIsStillAppliedWithWarning`, `CrlTest.RevokedInstanceCertificateIsReported` |
| CRL-04 | `pki crl` checks and installs the CRLs; `check-pki`, `status` and the metrics report on them | §7.6, §7.7 | 1.1 | `pki.sh` |

### 11.9 Configuration

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| CFG-01 | YAML configuration; all errors are reported, with their path; unknown key refused at every level | §8 | 1.0 | `Config.*`, fuzzing `fuzz_config` |
| CFG-02 | Validation rules of 8.3, shared by the service and the editor | §8.3 | 1.0 | `Validate.*`, Qt `validation_matches_service` |
| CFG-03 | Value formats: durations, sizes, percentages, IPv4 and IPv6 addresses and host names | §8 | 1.0 | `ParseDuration.*`, `ParseSize.*`, `ParsePercent.*`, `ParseEndpoint.*`, `IpRange.MatchesAddresses` |
| CFG-04 | Normalised writing of the configuration and the whitelist, read back identically | §8 | 1.1 | `ConfigWriter.*`, `WhitelistWriter.*`, `Units.FormatSizeAndPercentRoundTrip` |

### 11.10 Logging

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| LOG-01 | Levels `error`, `info`, `debug`, `trace`; categories `activity` and `config`; text or JSON format; file or standard error | §9 | 1.0 | `Logging.*`, `JsonFormatter.WritesOneObjectPerLine`, M05 |
| LOG-02 | Level changeable at runtime; log file reopened (rotation) | §9 | 1.0 | `AdminTest.LogLevelChangesAtRuntime`, `AdminTest.LogReopenStartsNewFileAfterRotation`, R10, M06 |
| LOG-03 | No key, token, secret or relayed data in the logs; data coming from a peer escaped | §9 | 1.0 | `AttackTest.TraceLogsContainNoSecretsNorRelayedData`, `AttackTest.PeerMessageCannotInjectLogLines`, R10 |

### 11.11 Lifecycle and administration

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| ADM-01 | systemd (`tlsrelay@N`) and Windows (`tlsrelay-N`) services, named instances, start with the system | §10, §10.3 | 1.0 | `tests/lifecycle/systemd.sh`, `windows-service.ps1`, M01 |
| ADM-02 | Graceful stop with drain (`shutdown_timeout`), immediate stop, restart; second Ctrl+C: immediate stop | §10 | 1.0 | `Relay.GracefulStopDrainsThenClosesRemainingChannels`, `Relay.SignalTriggersGracefulStop`, `Relay.SecondSignalForcesImmediateStop`, `Relay.AbortClosesChannelsImmediately`, `AdminTest.StopDrainsThenStops`, `AdminTest.KillStopsImmediately`, R12, M02, M03 |
| ADM-03 | Local administration channel (Unix socket, named pipe), restricted to administrators and the service account; each command logged with the caller | §10.1 | 1.0 | `AdminTest.SocketIsRestrictedToOwnerAndGroup`, `AdminTest.UnknownOrMalformedCommandsAreRefused`, fuzzing `fuzz_admin`, M04 |
| ADM-04 | Instance lock: a second execution of the same instance is refused | §10.1 | 1.0 | `AdminTest.SecondExecutionOfSameInstanceIsRefused` |
| ADM-05 | `status`, `channels`, `reload` (with outcome) and `check-config` commands; stopped instance reported | §10 | 1.0 | `AdminTest.StatusDescribesInstance`, `AdminTest.ChannelsListsOpenChannels`, `AdminTest.ReloadReportsWhatChanged`, `AdminTest.UnreachableInstanceIsReported`, R11 |
| ADM-06 | Configuration reload: log levels applied at runtime, other changes reported as requiring a restart | §10.2 | 1.0 | `AdminTest.ReloadReportsWhatChanged` |
| ADM-07 | Least-privilege services: `tlsrelay` account with only the `CAP_NET_BIND_SERVICE` capability, virtual account `NT SERVICE\tlsrelay-N` | §10.3 | 1.0 | `systemd.sh`, `windows-service.ps1`, M07 |
| ADM-08 | Metrics in Prometheus text format, read over the administration channel (series of 10.4) | §10.4 | 1.0 | `AdminTest.MetricsUsePrometheusTextFormat`, R11 |

### 11.12 Security and quality

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| SEC-01 | Hardened executables: PIE, full RELRO, stack protector, `_FORTIFY_SOURCE`; `/guard:cf`, DEP, ASLR on Windows | PLAN §5.4 | 1.0 | `tools/check-hardening.sh` and `.ps1` in CI |
| SEC-02 | No memory error or data race detected: sanitizers, fuzzing, static analysis without findings | PLAN §5.4 | 1.0 | CI: ASan and UBSan, TSan, fuzzing, clang-tidy, cppcheck, MSVC `/analyze` |
| SEC-03 | Resistance to attacks: fake server, hostile frames, flooding, log injection | PLAN §5.4 | 1.0 | `AttackTest.*`, [PENTEST.md](PENTEST.md) checklist (penetration test: manual) |
| SEC-04 | Dependencies without known vulnerabilities | PLAN §5.4 | 1.0 | `tools/check-deps.sh` in CI |

### 11.13 Performance

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| PERF-01 | 5,000 concurrent channels with data integrity | PLAN §5.6 | 1.0 | `tests/perf/perf.sh` (CI: 1,000 channels; measured: 5,000) |
| PERF-02 | 100 Mbit/s per channel | PLAN §5.6 | 1.0 | `perf.sh`, R04 |
| PERF-03 | Added latency below 1 ms (local) | PLAN §5.6 | 1.0 | `perf.sh`, R04 |
| PERF-04 | 72 h endurance with rotations, renegotiations and cuts: stable memory, descriptors and generations | PLAN §5.6 | 1.0 | `tests/perf/soak.sh` (4 min in CI; 72 h: manual) |

### 11.14 Delivery

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| PKG-01 | `.deb`, `.rpm` and `.msi` packages: installation, in-place upgrade, uninstallation | PLAN §4 | 1.0 | CI: package build, installation on 5 distributions, MSI installed, acceptance tests on the installed binaries, uninstallation |
| PKG-02 | Licence and third-party notices shipped with the packages | PLAN §4 | 1.0 | `packaging/test-linux-package.sh`, Windows CI (licence files) |
| PKG-03 | Delivery accompanied by the SHA-256 hashes of the packages | INSTALLATION §1 | 1.0 | CI: `tlsrelay-livraison` artifact (`SHA256SUMS`) |

### 11.15 tlsrelay-admin editor

| Id | Requirement | Ref. | Del. | Verification |
|---|---|---|---|---|
| EDT-01 | Editing of the configuration and the whitelist, validated by the service's rules, fields in error highlighted | §8.3, EDITEUR §2 | 1.1 | Qt `validation_matches_service`, `invalid_fields_are_marked`, `fields_without_object_are_hidden_unless_filled`, `whitelist_editor_round_trip_and_marks`, E02 |
| EDT-02 | Saving refused while errors remain; diff preview; original kept as `.bak`; atomic write | EDITEUR §3 | 1.1 | Qt `open_edit_save_with_preview_and_backup`, `save_refused_while_invalid`, `new_document_is_saved_normalized`, `diff_preview_lists_changes`, E03, E04 |
| EDT-03 | Export of a deployment package for Linux or Windows (configuration, whitelist, kit, CRL, script, instructions) | EDITEUR §4 | 1.1 | Qt `export_package_for_linux_and_windows`, E05 |
| EDT-04 | PKI module: open or create the mini-CA, inventory, signing, renewal, revocation and CRLs, audit log; passphrase never stored | EDITEUR §5 | 1.1 | Qt `pki_panel_full_cycle`, `pki_panel_refuses_wrong_passphrase_and_bad_directory`, `sign_dialog_inspects_request`, E06 to E09 |
| EDT-05 | Root-change wizard | EDITEUR §5 | 1.1 | Qt `pki_root_change_preparation`, E10 |
| EDT-06 | Shipped in the MSI ("tlsrelay-admin" feature, Qt 6 under LGPLv3, dynamic linking); headless `--check` | EDITEUR §1 | 1.1 | `Admin.CheckValid`, `Admin.CheckInvalid`, Windows CI step "Éditeur installé", E01 |

## 12. Open points

- Final package naming (phase 11).
- Decided in phase 6: metrics in Prometheus text format over the administration channel (§10.4); default paths on Windows under `%ProgramData%\tlsrelay\` (§10.3).
