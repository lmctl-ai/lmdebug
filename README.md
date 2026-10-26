# lmdebug

> The public README, docs, and examples for `lmdebug` are MIT under `LICENSE-examples`. Binary releases use `LICENSE`; implementation source and its history are maintained privately in `lmctlhq/lmdebug`.

**Linux network, system, process, packet-capture, and detection introspection in one self-contained executable, scripted from lmscript: structured JSON on the CLI, typed contexts (`net`, `sys`, `proc`, `detect`, `shark`) in the DSL, and an audited dry-run-by-default mutation framework.**

[![CI](https://github.com/lmctl-ai/lmdebug/actions/workflows/public-ci.yml/badge.svg)](https://github.com/lmctl-ai/lmdebug/actions/workflows/public-ci.yml)
[![Latest release](https://img.shields.io/github/v/release/lmctl-ai/lmdebug?label=release)](https://github.com/lmctl-ai/lmdebug/releases)
[![Examples: MIT](https://img.shields.io/badge/examples-MIT-blue.svg)](LICENSE-examples)

Every example in [`examples/`](examples/README.md) compiles against `lmdebug` and runs offline or against local kernel state with graceful degradation when elevated capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`) are absent. Run any example directly with `lmctl autorun`:

## Examples

### Networking, interfaces, routing, and sockets

| Example | Description |
| --- | --- |
| [`dns-lookup.lms`](examples/dns-lookup.lms) | Resolve `localhost` via `net.dns_lookup` and print every address |
| [`dns-query.lms`](examples/dns-query.lms) | Send a UDP RFC 1035 query via `net.dns_query` and inspect response records |
| [`interfaces.lms`](examples/interfaces.lms) | Enumerate interfaces, addresses, MTUs, and flags via `net.interfaces` |
| [`link.lms`](examples/link.lms) | Dump every link device and 64-bit RX/TX counters over rtnetlink via `net.links` |
| [`ethtool.lms`](examples/ethtool.lms) | Query link settings, driver info, and NIC statistics via `net.ethtool_link`/`driver`/`stats` |
| [`routes.lms`](examples/routes.lms) | Dump kernel IPv4/IPv6 routing tables over rtnetlink via `net.routes` |
| [`rule.lms`](examples/rule.lms) | Dump policy routing rules (`ip rule`-lite) over rtnetlink via `net.rules` |
| [`neigh.lms`](examples/neigh.lms) | Dump the ARP/NDP neighbor table (`ip neigh`-lite) over rtnetlink via `net.neighbors` |
| [`counters.lms`](examples/counters.lms) | Read `/proc/net/{snmp,netstat,snmp6}` protocol counters via `net.counters` |
| [`sockets.lms`](examples/sockets.lms) | List listening TCP sockets and owning processes via `net.sockets` |
| [`sockets-summary.lms`](examples/sockets-summary.lms) | Print per-family socket totals and TCP state counts (`ss -s`-lite) via `net.socket_summary` |

```sh
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/dns-lookup.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/dns-query.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/interfaces.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/link.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/ethtool.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/routes.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/rule.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/neigh.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/counters.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sockets.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sockets-summary.lms
```

### Active diagnostics, scanning, and TCP bridge

| Example | Description |
| --- | --- |
| [`scan.lms`](examples/scan.lms) | Parallel TCP connect port scan and boolean port check (`net.scan`, `net.check`) |
| [`pipe.lms`](examples/pipe.lms) | Blocking TCP socket objects (`net.tcp_listen`, `net.tcp_connect`) |
| [`trace.lms`](examples/trace.lms) | UDP traceroute hop list and RTTs (`net.trace`) |
| [`mtr.lms`](examples/mtr.lms) | Multi-cycle per-hop loss and latency statistics (`net.mtr`) |
| [`arping.lms`](examples/arping.lms) | Explicit-interface IPv4 ARP probe and validation (`net.arping`) |

```sh
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/scan.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pipe.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/trace.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/mtr.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/arping.lms
```

### System performance and sysctl planning

| Example | Description |
| --- | --- |
| [`sys-cpu.lms`](examples/sys-cpu.lms) | Aggregate and per-core CPU utilization deltas (`sys.cpu`) |
| [`sys-mem.lms`](examples/sys-mem.lms) | Physical memory, swap utilization, and PSI pressure (`sys.mem`) |
| [`sys-disk.lms`](examples/sys-disk.lms) | Per-device I/O byte rates, IOPS, await, and utilization (`sys.disk`) |
| [`sys-top.lms`](examples/sys-top.lms) | Top processes ranked by CPU, RSS, or disk I/O rate (`sys.top`) |
| [`sys-set.lms`](examples/sys-set.lms) | Read-only `/proc/sys` mutation plan (`sys.set`) |

```sh
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-cpu.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-mem.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-disk.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-top.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-set.lms
```

### Process inspection

| Example | Description |
| --- | --- |
| [`proc-list.lms`](examples/proc-list.lms) | Process table enumeration with CPU, RSS, open-FD, and socket counts (`proc.list`) |
| [`proc-show.lms`](examples/proc-show.lms) | Deep inspection of one PID: FDs, sockets, memory maps, and rlimits (`proc.show`) |

```sh
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/proc-list.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/proc-show.lms
```

### Detection, persistence autoruns, hashes, and quarantine

| Example | Description |
| --- | --- |
| [`detect-scan.lms`](examples/detect-scan.lms) | YARA file and directory scanning with embedded builtin rules (`detect.scan`) |
| [`detect-autoruns.lms`](examples/detect-autoruns.lms) | Linux persistence enumeration across systemd, cron, shell rc, and `ld.so` (`detect.autoruns`) |
| [`detect-hashes.lms`](examples/detect-hashes.lms) | Offline SHA-256/MD5 exact-file signature scan (`detect.hashes_scan`) |
| [`detect-quarantine.lms`](examples/detect-quarantine.lms) | Read-only file quarantine plan (`detect.quarantine`) |

```sh
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/detect-scan.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/detect-autoruns.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/detect-hashes.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/detect-quarantine.lms
```

## Use it

The current release lane publishes `lmdebug-linux-x64` and `lmdebug-linux-arm64`, built against dynamic glibc >= 2.35 with all third-party libraries (`iputils` ping, `iperf3`, `libpcap`, `libyara`) and C++ runtimes linked statically. Download from the [releases](https://github.com/lmctl-ai/lmdebug/releases), or let `lmscript` fetch it: a program is a `_dsl_` (or `_lmcode_`) block compiled by `lmscript` (`npm i -g @lmctl-ai/lmctl`), which finds `lmdebug` on `PATH` or downloads the release on first use (`install=`).

```lms
# show.lms: inspect interfaces and listening TCP sockets
p = _lmcode_ cli="lmdebug" install="github:lmctl-ai/lmdebug@latest";
let ifs = net.interfaces();
for (i in range(0, ifs.len())) {
  let iface = ifs.at(i);
  println(iface.name() + " " + iface.addr() + " mtu=" + str(iface.mtu()));
}
let s = net.socket_summary("");
println("listening sockets: " + str(s.listening()));
end _lmcode_
savedsl(p, "show.dslb");
r = system ${dsl_cli(p)} --dsl show.dslb;
for (l in lines(r.stdout)) { println(l); }
assert(r.code == 0);
```

```sh
lmscript show.lms
lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/interfaces.lms
```

## What is in the box

See [`docs/cli-and-dsl.md`](docs/cli-and-dsl.md) for the complete CLI and DSL reference.

| Domain | CLI subcommands | DSL context and methods |
| --- | --- | --- |
| Capabilities & meta | `lmdebug caps` | `context lmdebug: Meta` — `caps_json()`, `apply_enabled()`, `force_enabled()`, `changes_remaining()` |
| Networking | `dns`, `dig`, `ifaddrs`, `link`, `link set`, `ethtool`, `route`, `rule`, `neigh`, `counters`, `sockets`, `trace`, `tracepath`, `mtr`, `arping`, `scan`, `pipe`, `ping`, `iperf3` | `context net: Net` — `dns_lookup`, `dns_query`, `interfaces`, `links`, `link_set`, `ethtool_link`, `ethtool_driver`, `ethtool_stats`, `routes`, `rules`, `neighbors`, `counters`, `sockets`, `socket_summary`, `trace`, `mtr`, `arping`, `scan`, `check`, `tcp_connect`, `tcp_listen` |
| System performance & sysctl | `sys cpu`, `sys mem`, `sys disk`, `sys top`, `sys set` | `context sys: Sys` — `cpu`, `mem`, `disk`, `top`, `set` |
| Process inspection & control | `proc [list]`, `proc show`, `proc kill` | `context proc: Proc` — `list`, `show`, `kill` |
| Detection & remediation | `detect scan`, `detect autoruns`, `detect hashes import\|scan\|status`, `detect quarantine`, `detect restore` | `context detect: Detect` — `scan`, `autoruns`, `hash_import`, `hashes_scan`, `quarantine`, `restore` |
| Packet capture & analysis | `lmdebug pcap` | `context shark: Shark` — pcap/pcapng readers/writers, packet builders, dissectors, flows, TCP streams, display/cBPF filters, `interfaces`, `compile_filter`, `live` |

The full list of signatures: `lmdebug --dsl-signatures` (and `lmdebug pcap --dsl-signatures`); the schema: `lmdebug --dsl-schema --json` (and `lmdebug pcap --dsl-schema --json`).

## Honest limits

- Active raw-socket probes (`trace`, `tracepath`, `mtr`, `arping`, and `shark.live`) require root or `CAP_NET_RAW`; `link set` requires `CAP_NET_ADMIN`. Without those privileges, DSL methods return structured error strings in `.error()` rather than aborting the VM.
- `trace`, `tracepath`, `mtr`, and `arping` are IPv4-only in the current release.
- `scan` performs unprivileged TCP connect scans (`open`, `closed`, `filtered`); it does not perform raw SYN or UDP scanning.
- `pipe` is a single-connection TCP bridge (no UDP, TLS, or Unix domain sockets).
- Mutating verbs (`link set`, `sys set`, `proc kill`, `detect hashes import`, `detect quarantine`, `detect restore`) are dry-run by default and never write unless `--apply` is passed on the CLI invocation.

## Resource limits

A program may use at most 4096 MiB in total; beyond that it stops with a run error (exit 3) naming the limit instead of exhausting the machine. Set `LMDEBUG_MAX_MEMORY_MB` to change it (a positive whole number; anything else is a usage error, exit 2). `lmdebug --dry-run --dsl prog.dslb` runs a program without mutating host state and prints the `lmscript.host_plan.v1` effect plan.

```text
usage: lmdebug --version | caps | sys ... | proc ... | detect ... | pcap ... | --dsl-schema [--json] | --dsl-signatures | [--dry-run] --dsl FILE [FILE ...]
```

## License

The README, docs, and `examples/*.lms` are MIT-licensed under [`LICENSE-examples`](LICENSE-examples).
Binary releases are licensed under [`LICENSE`](LICENSE) (Lattice Systems Binary License 1.0). Third-party components remain under their own licenses and notices in [`THIRD_PARTY_NOTICES`](THIRD_PARTY_NOTICES).
