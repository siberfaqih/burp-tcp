# Burp Raw TCP extension (Phases 4B–5)

Montoya API extension that provides the Burp Suite control plane for the
`rawtcp-engine` SOCKS5 relay. It connects to the engine's authenticated
localhost IPC server (Phase 4A) over a binary WebSocket and renders five
workspace tabs: **Intercept**, **TCP history**, **Repeater**, **Decoder**, and **Connections**.

The extension holds no relay state of its own. All connection, history, and
interception data lives in the engine and is fetched on demand, so unloading
the extension only closes the socket — it cannot orphan control state.

## Requirements

- Java 21 (built and tested against Temurin/OpenJDK 21).
- Maven 3.9+.
- Burp Suite (recent release) to load the built extension.
- The Montoya API and protobuf tooling are pulled from Maven Central; no
  local `protoc` or Burp installation is needed to build.

## Build

```bash
cd extension
mvn clean verify          # compiles proto, runs tests, produces the jar
```

Output: `target/rawtcp-burp-extension-0.1.0.jar` — a single shaded jar with
`protobuf-java` bundled and the Montoya API excluded (Burp supplies it).

The canonical schema `../proto/burp_tcp.proto` is compiled by `protoc`
(downloaded by the Maven plugin) into `com.rawtcp.burp.ipc.proto.BurpTcp`.

## Run

1. Start the engine with the control plane enabled:

   ```bash
   rawtcp-engine --port 1080 --ipc-port 8080
   ```

   The engine prints:

   ```text
   IPC control plane listening on 127.0.0.1:8080
   IPC capability token: <uuid>
   IPC daemon epoch: <uuid>
   ```

2. In Burp: **Extensions → Installed → Add**, select the jar.
3. Open the **Raw TCP** suite tab, enter the IPC port and paste the
   capability token, then click **Connect**.

The token is per-launch: restarting the engine invalidates it. Port and token
are remembered in Burp preferences between sessions.

## Tabs

- **Connections** — live sessions from `ListConnections`. Selecting a row
  drives the History tab.
- **TCP history** — one passive log of every forwarded chunk across all
  connections, newest last, like Burp's HTTP history. Nothing needs selecting
  first: traffic appears on its own while Live is on. The connection dropdown
  is only a filter (default All connections); picking a Connections row
  filters here, and the filter resets to all if that connection vanishes.
  Direction filter, literal text/hex search, and numeric sorting apply locally
  without new fetches. Right-click a row → **Send to Repeater**,
  **Send to Decoder**, or **Copy bytes as hex**. Selection survives refresh;
  with nothing selected the newest chunk is shown. Each cycle re-reads only
  connections whose byte counters moved, so a quiet tab costs almost no RPC.
- **Intercept** — directional enable toggles, queue count, and an inline
  hex/text editor. **Forward** sends the original bytes or commits a
  replacement when edited, then selects the next held unit. **Forward all**
  releases every held unit unchanged (oldest first) without disabling
  interception — use it to unblock multi-packet handshakes fast, since each
  held round trip otherwise waits for its lease. **Drop bytes**
  suppresses only that chunk; **Close connection** terminates the session.
  Edits follow the unit ID/revision through refreshes and row switches.
  The editor shows the engine's auto-release deadline; expired/revised units
  never inherit another unit's edit. Errors appear inline rather than in
  modal dialogs. **Restore original** discards the current edit.
  The stats line includes **Bypassed (queue full)**: units forwarded
  untouched because the engine queue was full — if this number grows while
  connections run past intercept, the queue (default 128) is the bottleneck,
  not the proxy rules.
  A replacement that changes the byte size warns inline after commit, because
  length-framed protocols (HTTP, TDS) may reject it. A raw-text edit that
  breaks a complete HTTP/1.x `Content-Length` message is refused before
  sending, with exact declared-vs-actual numbers — edit via Body parameters
  (which updates the header) or fix the header manually. Chunk fragments,
  chunked/compressed bodies, and non-HTTP payloads are never auto-modified.
  A unit past the first slice of its stream is labelled
  `stream slice #N`: Drop/Replace there alters a running transfer and Close
  breaks it — that is how truncated downloads (half a JSON array, a heartbeat
  answered with nothing) happen.

### Bulk transfers, downloads, and heartbeats

Each held unit is one ~16 KiB TCP read, not one message. A 50 MB download is
thousands of units: the 128-slot engine queue fills instantly and the rest
bypasses intercept untouched (watch `Bypassed (queue full)` in the stats
line). The few units you do see are random mid-stream slices — editing,
dropping, or closing them corrupts the transfer while the app times out
waiting. Heartbeats are worse: holding one longer than the app's heartbeat
interval logs you out by design.

Playbook: keep `Intercept to client` OFF during bulk downloads and let
responses flow; intercept `to server` (requests) only. When the queue backs
up, **Forward all** releases everything unchanged without disabling policy.
Never Drop/Close a `stream slice #N>1` unless breaking that transfer is the
point. If connections run past intercept while both toggles are on, check
`Bypassed (queue full)` (queue saturated) and `Expired` (units auto-released
after the 30 s lease because nobody decided in time).
  The selected UTF-8/Hex view persists through queue changes, Forward, and
  restoring a draft. Binary that cannot decode as UTF-8 remains a read-only
  text preview in UTF-8 mode; Forward still uses the original bytes.
- **Repeater** — one explicitly approved manual TCP send per click. Each send
  opens a fresh engine-side TCP session, writes the payload exactly once,
  captures a bounded response under an explicit completion policy, and then
  closes. Status polling only reads the accepted operation; it never resends.
  Each history/intercept import opens a separate destination-populated draft
  without sending. Up to 16 independent drafts can be open; there is one
  active send per IPC session, with the other drafts remaining editable.
  The request editor and parameter sidebar sit above the response view.
  Close unused drafts to release their local data.
- **Decoder** — standalone UTF-8 URL encoder/decoder, with form (`+` as space)
  and URL-component modes. Each click decodes one layer; use **Use output as
  input** to explicitly decode another layer. Invalid escapes/UTF-8 are reported
  rather than replaced. Traffic imported into Decoder does not alter a held unit.

### Body parameter workflow

The Intercept and Repeater editors detect `name=value&...` form data in the
current TCP chunk. Detection is ASCII-only: proper form encoding is ASCII
(non-ASCII must be percent-encoded), so raw UTF-8 or binary blobs stay in
the raw editor instead of being misread as parameters. The **Body parameters** sidebar displays decoded names and
values. Edit a cell and click **Forward** / **Send**: the active cell is committed
and the edited component is encoded back into the wire payload automatically.
The raw/hex view updates immediately. Names can be edited too; duplicate names,
ordering, empty values, bare flags and untouched escape spellings are preserved.
`+` decodes as space, `%2B` as a literal plus, and `%252F` decodes once to `%2F`.
Field edits support undo/redo. The **Parameters** checkbox hides the sidebar.

For an entire HTTP/1.x `application/x-www-form-urlencoded` message present in
one chunk, editing updates `Content-Length` using encoded byte length. Both
CRLF and LF-only line endings are accepted (pasted requests are often
LF-only); the original style is preserved on rebuild. A single trailing line
break on a pasted bare form is kept outside the fields. Partial,
chunked, compressed, non-UTF-8 or ambiguous HTTP bodies stay in the raw editor;
the UI does not reassemble messages across TCP chunks. Detection is bounded to
64 KiB and 512 parameters. JSON/multipart bodies are not interpreted as forms.

The raw editor's **URL encode / URL decode** buttons manually transform selected
UTF-8 text (or all text when nothing is selected). These are explicit wire edits;
use the parameter sidebar for automatic decode → edit → re-encode behavior.

Traffic tables show destination, traffic direction, byte size, time and a readable
preview. Unit IDs, sequence numbers, offsets and revisions are available as row
tooltips rather than primary columns.

### Keyboard workflow

- **Ctrl+Enter** (macOS **Cmd+Enter**): Forward in Intercept, Send in Repeater.
- **Ctrl+R** (macOS **Cmd+R**): selected history/intercept bytes → new Repeater draft.
- **Ctrl+Z / Ctrl+Y** (macOS **Cmd+Z / Cmd+Y**): undo/redo in the byte editor.

History remains connection-scoped. TCP chunks are not application messages:
importing one chunk does not reconstruct a full protocol conversation. Repeater
opens a fresh connection, so it does not inherit authentication or session state.
An evicted/unknown destination leaves the draft target empty for manual entry.

## Wire protocol

One binary WebSocket frame carries exactly one raw protobuf message (no
length prefix). The first frame is a `Hello` carrying the capability token;
the engine replies with `HelloAck` or closes on a mismatch. See
`../proto/burp_tcp.proto` and `../engine/src/ipc.rs`.

`WireFormatTest` and the Rust `ipc::proto::tests` module assert identical
golden byte sequences, pinning both implementations to the same encoding.

## Design notes

- **No EDT blocking** — all network I/O runs on background threads; every
  RPC returns a `CompletableFuture`, and listener callbacks marshal UI
  updates with `SwingUtilities.invokeLater`.
- **Generation-isolated connections** — each connection attempt owns its
  own socket, frame buffer, pending map, and close latch, and each connection
  loop has an identity a restart invalidates. `stop()` aborts every live
  attempt, so a superseded loop can neither publish nor authenticate a
  socket. Callbacks and send tasks capture the attempt they belong to, so a
  late `onClose` or a stale in-flight send can never touch the current
  connection. Teardown always physically closes the socket, including on a
  protocol error or a send timeout, so an authenticated controller is never
  orphaned. The handshake is driven asynchronously; the loop waits on an
  interruptible latch, so stopping during a slow upgrade returns promptly.
- **Serialized sends** — frames are chained through completion on a single
  thread, so the next frame does not start until the previous send future
  completes (bounded by a 10s timeout). Frame order holds under WebSocket
  backpressure; the pending-request map is capped at 256 atomically.
- **Authoritative state** — the Intercept toggles read the engine's
  reported `Stats.c2s_enabled`/`s2c_enabled`, revert immediately to the last
  authoritative state if a `SetEnabled` fails (even if a follow-up `Stats`
  also fails), and are reconciled periodically so an external policy change
  is adopted without a local toggle.
- **Captured-unit decisions** — a decision commits against the edited unit
  and revision captured at click time, independent of later snapshots. Duplicate
  clicks are suppressed until the result arrives. Late completions from a
  disconnected controller cannot repopulate the queue.
- **Stale-snapshot guards** — Connections, History, and Intercept tag each
  request with a sequence number and drop responses that no longer match
  the current connection; a new daemon epoch clears connection-scoped
  state.
- **Binary safety** — payloads are only rendered through `HexText`; the
  text view is lossy and explicitly marked, while hex is authoritative.
  Switching the editor between hex and text converts bytes (never
  reinterpreting hex digits as literal text). Invalid UTF-8 in Text mode is a
  read-only preview backed by preserved original bytes. Switching to Hex enables
  exact binary edits; viewing a payload never silently changes its wire bytes.
- **Reconnect** — the client reconnects with a fixed delay, re-runs the
  handshake, and re-snapshots state on `onConnected`. The engine's protocol
  version is validated during the handshake and a mismatch tears the
  connection down.
- **Restart isolation** — each connection loop's identity is captured by
  `start()` under the same monitor as `stop()`, before its thread launches,
  so a delayed or interrupted old loop cannot supersede the live one.
  `stop()` aborts every live attempt, the socket reference is atomic, and a
  `Hello` completing after teardown cannot publish state. Disconnect
  notification is delivered under the lifecycle monitor, so an old disconnect
  cannot disable a newer session. `RawTcpPanel` carries a session epoch and a
  terminal `disposed` flag so a listener callback queued before a disconnect —
  or arriving after unload — cannot re-enable controls.
- **One-shot repeater** — each Send opens a fresh engine-side TCP session,
  writes the payload exactly once, captures a bounded response under the
  selected close/exact-byte/idle policy, and closes. The tab disables Send
  while an operation is active, stops only the accepted send ID, polls status
  without resending, and drops stale completions on disconnect.
- **Terminal unload** — `close()` marks the client closed before stopping, and
  `start()` refuses once closed, so a connect action racing extension unload
  cannot leave an authenticated controller behind.
- **Unload safety** — the registered unloading handler calls
  `RawTcpPanel.dispose()` (stopping the status timer and detaching the
  listener) and closes the client; the engine treats the last controller
  leaving as a fail-open disable.

## Tests

`mvn clean verify` runs 82 tests, including seven workflow regressions
(`WorkflowTest`) for edited/reordered queues, revision changes, disconnect
isolation, filtered/sorted history routing, exact target/byte transfer to
Repeater, the shared send slot across drafts, and lossless binary editing.
`BodyEditingTest` and `FormBodyTest` cover sticky UTF-8, active-cell Forward,
non-disruptive refresh, one-step undo, selected-text URL tools, duplicate fields,
unchanged-byte preservation, HTTP byte-length correction, and malformed input.
The existing IPC, lifecycle, cancellation, and wire-format tests also run.

The UX revision has automated Java verification and off-screen Swing layout
inspection on macOS. In-Burp Windows usability acceptance is still pending.
