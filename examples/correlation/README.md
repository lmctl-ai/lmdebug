# HTTPS Packet & TLS 1.3 Flight Correlation (`examples/correlation/`)

This multi-host example combines `lmdebug pcap` (packet dissection, TCP sequence/retransmission analysis, and field export) with `lmssl` (TLS 1.3 X.509 certificate verification, SHA-256 trace verification, and `ssl.monotonic_us()` steady-clock segment timings) to correlate an HTTPS exchange from TCP establishment through TLS 1.3 flights, HTTP/1.1 transfer, and connection teardown.

## Entry points

| Example | Requirements | Run | Outputs (`build/examples/correlation/offline/`) |
| --- | --- | --- | --- |
| [`https-packets-offline.lms`](https-packets-offline.lms) | Unprivileged, offline, deterministic; requires `lmdebug` (`v0.1.20+`) and `lmssl` (`v0.2.0+`) on `PATH` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/correlation/https-packets-offline.lms` | `request.json`, `tls-trace.txt`, `capture.pcapng`, `packets.csv`, `steps.json`, `steps.csv`, `report.md` |
| [`correlate_https.py`](correlate_https.py) (`--self-test`) | Unprivileged, offline unit/fixture self-test suite | `python3 examples/correlation/correlate_https.py --self-test` | Regression assertions across 8 correlation scenarios |

Regenerate the deterministic offline fixtures under [`fixtures/`](fixtures/) at any time with:

```sh
./examples/correlation/generate-fixtures.sh
```

## How correlation works and honesty limits

### 1. TLS 1.3 encrypted flight attribution (`exact` vs `flight` vs `ambiguous`)

Per [RFC 8446 §2](https://www.rfc-editor.org/rfc/rfc8446.html#section-2), TLS 1.3 encrypts all handshake messages after `ServerHello` inside outer `ApplicationData (23)` records. Multiple handshake messages (`EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`, `NewSessionTicket`) can be coalesced into a single TLS record or TCP segment, or a large message such as `Certificate` can span multiple records and TCP segments.

Without exporting TLS traffic secrets (`SSLKEYLOGFILE`), packet dissectors cannot decrypt outer `ApplicationData (23)` records into individual handshake messages. Therefore:

- **`exact` evidence** is reported **only** for:
  - Captured TCP 3-way handshake events (`TCP SYN`, `TCP SYN-ACK`, and `TCP Establishing ACK`, including when the establishing ACK piggybacks initial `ClientHello` bytes).
  - Unambiguous single-packet visible `ClientHello` and `ServerHello` records recognized by `lmdebug pcap`.
  - Captured TCP teardown packets (`FIN`/`ACK` or `RST`).
- **`flight` evidence** is reported for encrypted post-`ServerHello` handshake messages (`EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Server Finished`, `Client Finished`, `NewSessionTicket`), split/coalesced hellos, and `HTTP Request` / `HTTP Response` application data:
  - OpenSSL `SSL_trace` (`Tls.trace()`) serves as the authoritative **message-order spine** confirming that each message was sent or received and recording its plaintext handshake body length (`trace_len`).
  - `packet_ids` is left empty (`[]` in JSON, blank in CSV) for encrypted messages so the report never fabricates a 1-to-1 decrypted packet claim from payload lengths.
  - `candidate_packet_ids` lists all captured TCP data packets belonging to that directional TLS flight.
- **`ambiguous` evidence** is reported when server handshake and post-handshake/application encrypted packets cannot be separated by an intervening client flight.
- **`app_only` / `missing` evidence** is reported when a message is present in `SSL_trace` or application calls without corresponding captured packets, or when capture starts after `SYN` (`has_syn=false`) or ends before `FIN`/`RST` (`has_fin_teardown=false`).
- **TCP retransmissions** (`tcp.analysis.retransmission`) are preserved as separate rows in `packets.csv` (with `retransmission=true`) and included in `candidate_packet_ids`, never turned into extra protocol steps. Sequence number ranges use unsigned 32-bit arithmetic modulo $2^{32}$.
- **Profile check:** Correlation targets TLS 1.3 (`min_version("TLSv1.3")`, `max_version("TLSv1.3")`, ALPN `http/1.1`). If a connection negotiates TLS 1.2, correlation refuses with `status="unsupported_profile"` rather than mislabeling TLS 1.2 flights with TLS 1.3 semantics.

### 2. Separate time axes (`ssl.monotonic_us()` vs `pkt_time`)

Application segment timings (`dns_us`, `tcp_connect_us`, `tls_handshake_us`, `request_write_us`, `ttfb_us`, `transfer_us`, `eof_us`, `close_call_us`) are measured inside `lmssl` using `ssl.monotonic_us()` (`std::chrono::steady_clock` microseconds from a process-local origin). First-byte TTFB is measured with an initial 1-byte `tls.read(1)` before draining the remaining response so header/body buffering never inflates TTFB.

Packet timestamps (`rel_us`, `delta_us`, `pkt_first_us`, `pkt_last_us`) come from `libpcap`/pcapng capture timestamps relative to the first captured `SYN` (or first captured tuple packet when `SYN` is absent).

Because the `lmssl` steady clock and `libpcap` packet timestamps have different clock origins in separate processes, **they are never subtracted from each other**. Both axes are displayed side-by-side in `steps.json`, `steps.csv`, and `report.md`, joined by the verified 4-tuple (`Conn.local()` and `Conn.peer()`) and protocol flight order.

### 3. Close and teardown semantics (`tls.shutdown()` vs TCP `FIN`/`RST`)

In `lmssl`, `tls.shutdown()` performs a single `SSL_shutdown` call (`close_call_kind="tls_shutdown_attempt"`) to emit a TLS `close_notify` alert and does not wait for a bidirectional close handshake or close the underlying TCP file descriptor. Consequently:

- `close_call_us` measures only the local `tls.shutdown()` API call duration.
- Actual wire-level TCP disconnect latency (`disconnect_us`, `disconnect_status="fin_teardown"` or `"rst_teardown"`) is reported on the capture axis only when `lmdebug pcap` observes the `FIN`/`ACK` or `RST` teardown packets for the connection tuple.

### 4. Live capture privileges

Use `shark.interfaces()` in `lmdebug pcap` to enumerate capture devices and addresses without elevated privileges. Opening a live Linux capture handle (`shark.live(...)`) requires `root` or `CAP_NET_RAW` (for example on a dedicated local binary copy via `sudo setcap cap_net_raw=eip /path/to/lmdebug`). Note that `lmdebug caps` describes general host command support, not whether an unprivileged user can open a live capture device; `shark.interfaces()` and `shark.live()` provide the capture-specific probe and actionable `CAP_NET_RAW` guidance.
