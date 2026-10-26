# Request Segment Timing (`examples/segment/`)

These examples measure application-observed request segments with `lmssl` `ssl.monotonic_us()` (released in `lmssl` `v0.2.0`) and collect non-timed interface/route context from `lmdebug` (`ifaddrs` and `route`). They do **not** capture packets or require `CAP_NET_RAW`.

| Example | Network / privileges | Run | Artifacts (`build/segment/<name>/`) |
| --- | --- | --- | --- |
| [`local-https-timing.lms`](local-https-timing.lms) | Loopback only, unprivileged; starts a local ephemeral CA + HTTPS 1.1 fixture server | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/segment/local-https-timing.lms` | `report.json`, `segments.csv`, `report.md`, `checkpoint.json` |
| [`local-tcp-timing.lms`](local-tcp-timing.lms) | Loopback only, unprivileged; starts a local framed TCP fixture server | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/segment/local-tcp-timing.lms` | `report.json`, `segments.csv`, `report.md`, `checkpoint.json` |

## Segment definitions and caveats

- **All durations come from `ssl.monotonic_us()`** inside one `lmssl` process (`format_version: 1`, `kind: "segment_timing"`). The Python supervisor (`timing.py`) enforces a bounded process-group deadline (default 20 s) and 1 MiB output/response caps; its own clock is diagnostic only and never reported as a request segment.
- **No double hostname resolution:** `net.resolve(host)` is timed once (`dns_us`); `net.connect(selected_numeric_ip, port)` connects to the numeric IP (`tcp_connect_us`) while `ctx.connect(conn, original_hostname)` preserves the original hostname for SNI and X.509 certificate verification (`tls_handshake_us`).
- **True first-byte TTFB:** `ttfb_us` is measured from the completion of `write()` to the return of an initial `read(1)`. Subsequent reads drain up to the response cap (`transfer_us`), and the final zero-byte EOF read is recorded separately (`eof_observation_us`). One-byte responses have `transfer_us == 0`; empty or failed responses report `null` for `ttfb_us` and `transfer_us` rather than a misleading zero.
- **Close and wire-disconnect boundaries:** `Tls.shutdown()` issues one `SSL_shutdown` notification (`close_call_kind: "tls_shutdown_attempt"`), and plain TCP `Conn.close()` closes the local descriptor (`close_call_kind: "tcp_local_close"`). Without packet capture, full two-way TCP FIN/ACK teardown is not observed (`disconnect_us: null`, `disconnect_status: "not_observed_without_capture"`).
- **Raw wire bytes:** `transfer_us` covers raw HTTP/1.1 status, headers, and body bytes; chunked transfer-encoding wire bytes are timed without claiming decoded-body validation.
