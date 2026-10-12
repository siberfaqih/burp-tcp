# burp-tcp — Raw TCP relay engine + Burp Suite extension

A loopback SOCKS5 TCP relay with passive capture, manual interception, and a
Burp Suite control-plane UI (connections, unified TCP history, intercept,
multi-draft repeater, URL decoder). Built clean-room: this repository contains
only original code — no vendor binaries, no decompiled material, no internal
planning documents.

## Components

| Path | What it is |
|---|---|
| `engine/` | Async Rust relay: SOCKS5 CONNECT listener, bidirectional forwarding, bounded in-memory capture, revisioned manual interception, authenticated loopback IPC server, one-shot TCP repeater |
| `extension/` | Montoya (Burp Suite) extension in Java 21: workspace UI over the IPC control plane |
| `proto/` | Canonical IPC schema (`burp_tcp.proto`), shared by the Rust server and the Java client |
| `testlab/` | Local TCP/SOCKS fixtures used by the engine test suites |
| `.github/workflows/` | Windows CI: fmt, Clippy, Rust tests, extension build, `rawtcp-engine.exe` + `.jar` packaging with SHA-256 sums |

## What it does

- **Standalone SOCKS5 CONNECT relay** on `127.0.0.1:1080`: NO AUTH, IPv4/domain
  targets, segmented negotiation, truthful replies, half-close preservation,
  bounded memory, graceful shutdown. Refuses non-loopback binds.
- **Passive capture**: every forwarded byte run is recorded with connection
  ID, direction, per-direction sequence/offset, and UTC + monotonic
  timestamps (bounded FIFO storage).
- **Manual interception**: opt-in per direction. Each held unit is one TCP
  read (~16 KiB), committed exactly once as Forward / Replace / Suppress /
  Close under a finite hold lease; full queue or expired lease fails open to
  Forward. A replacement that breaks a complete HTTP/1.x `Content-Length`
  framing is refused client-side before sending.
- **IPC control plane** (Phase 4A): binary WebSocket protobuf RPC on
  `127.0.0.1`, capability-token handshake, per-launch daemon epoch.
- **Burp extension** (Phase 4B): live Connections list; unified TCP history
  across all connections (search, direction filter, hex/text views, decoded
  body parameters, Send to Repeater/Decoder); inline Intercept editor with
  URL encode/decode, form body parameters with automatic re-encoding, and
  stream-slice warnings; Repeater workspace with independent drafts sharing
  one send slot; offline URL Decoder tab.
- **One-shot TCP repeater** (Phase 5): one approved send per click on a fresh
  engine-side connection, bounded response capture, no retries.

## Updates in this push

- Engine: capture/history core, manual interception coordinator, IPC server,
  repeater, and Windows CI (previously only the Phase 1A relay was published).
- Extension: full workspace UI as described above, with framing guards
  (Content-Length consistency, size-change warnings, mid-stream slice
  labels) and LF-tolerant form parsing.
- New root README, GitHub Actions Windows build, and versioned release
  artifacts (see Releases).

## Build

Requires Rust 1.89+ and, for the extension, Java 21 + Maven 3.9+.

```bash
cargo test --workspace --locked   # engine + fixtures (fmt/clippy clean, warnings denied)
cargo build --release --locked    # -> target/release/rawtcp-engine

cd extension
mvn clean verify                  # -> target/rawtcp-burp-extension-0.1.3.jar
```

Windows binaries are built natively by CI (`.github/workflows/build-windows.yml`).

## Run

```bash
rawtcp-engine --port 1080 --ipc-port 8080
```

The engine prints the IPC endpoint, a per-launch capability token, and the
daemon epoch. In Burp Suite: Extensions → Add the `.jar`, open the Raw TCP
tab, enter the IPC port, paste the token, Connect. Route the target
application through `127.0.0.1:1080` as its SOCKS5 proxy.

## Scope and limits (read before pentesting bulk transfers)

- Loopback only. No TLS interception, no UDP, no message reassembly:
  interception holds TCP *chunks*, not application messages. Each connection
  holds at most one chunk per direction; download size alone does not fill
  the 128-slot queue. Many concurrent streams can exhaust it. Use Forward all
  to release held units unchanged, or disable an unneeded direction.
- Never Drop/Close a `stream slice #N > 1` unless breaking that transfer is
  the intent; a truncated stream surfaces in the app as a cut connection or
  a half-parsed document.
- Holding traffic can exceed application-specific timeouts, including
  heartbeat deadlines. The resulting behavior depends on the protocol.
- Diagnose from the Intercept stats line: rising `Bypassed (queue full)` =
  saturated queue; rising `Expired` = units auto-released after the 30 s
  lease because nobody decided in time.
- The banner under the connect bar always shows engine epoch, the
  `app proxy →` address the target must use, live policy, and live/held
  counts plus cumulative admitted SOCKS sockets (`accepted`). Red
  `NOT CONNECTED` shows the last disconnect reason. The engine reports bad
  tokens explicitly; after restarting it, paste the new token. Last-controller
  loss disables interception: check and re-enable the desired directions after
  reconnecting.
- The Connections **Ended** column shows why each closed session ended.
  Failed SOCKS CONNECT attempts are retained here too, with no fabricated
  payload. History visits all connections with two outstanding queries at
  most, bounded to 300 chunks / 1 MiB per direction per response. The UI cache
  retains up to 8192 chunks / 16 MiB; `newest K of N` reports truncation.
- One engine at a time: a second `rawtcp-engine.exe` cannot bind the same
  ports and exits. If Burp was killed instead of unloaded, the engine reaps
  the half-open controller after 60 s idle and frees its slot.

## Troubleshooting missing traffic

- `SOCKS5 CONNECT ... 0x05 (connection refused)` means the proxy received the
  request, but the OS refused the upstream TCP connection. Check **Connections
  → Ended**. No application traffic exists to intercept or capture until
  CONNECT succeeds. From the engine machine, test with
  `Test-NetConnection <host> -Port <port>` on Windows.
- Exclude `rawtcp-engine.exe` from ProxyBridge proxy rules to avoid routing
  the engine's upstream sockets back into itself. Route the target process
  through the SOCKS address shown in the banner.
- An unanswered IPC RPC times out after 15 seconds and triggers reconnect.
  Decisions and Repeater sends are never automatically replayed; their outcome
  may be unknown. Recheck the directional policy after reconnecting.
- Capture is bounded and lossy under pressure. **History drops** counts lock
  contention losses; FIFO eviction and snapshot limits also remove older
  chunks from view. Live byte counters track forwarding independently of
  capture retention.

## Releases

Versioned Windows assets (`rawtcp-engine.exe`,
`rawtcp-burp-extension-0.1.3.jar`, `SHA256SUMS.txt`) are attached to GitHub
Releases, built by CI on `windows-latest`.
