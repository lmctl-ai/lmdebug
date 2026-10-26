# lmdebug examples

Each example in `examples/` compiles against the `lmdebug` host (`install="github:lmctl-ai/lmdebug@latest"`) and exercises a network, system, process, or detection workflow:

| Example | What it shows | Run |
| --- | --- | --- |
| [`dns-lookup.lms`](dns-lookup.lms) | Resolve `localhost` and print every address via `net.dns_lookup` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/dns-lookup.lms` |
| [`dns-query.lms`](dns-query.lms) | Send a UDP RFC 1035 query and inspect `DnsResponse` records via `net.dns_query` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/dns-query.lms` |
| [`interfaces.lms`](interfaces.lms) | Enumerate interfaces, addresses, MTUs, and flags via `net.interfaces` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/interfaces.lms` |
| [`link.lms`](link.lms) | Dump every link device and 64-bit RX/TX counters via `net.links` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/link.lms` |
| [`ethtool.lms`](ethtool.lms) | Query link settings, driver metadata, and NIC statistics via `net.ethtool_*` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/ethtool.lms` |
| [`routes.lms`](routes.lms) | Inspect kernel routing tables (`ip route show table all`-lite) via `net.routes` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/routes.lms` |
| [`rule.lms`](rule.lms) | Dump policy routing rules (`ip rule`-lite) via `net.rules` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/rule.lms` |
| [`neigh.lms`](neigh.lms) | Dump the ARP/NDP neighbor table (`ip neigh`-lite) via `net.neighbors` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/neigh.lms` |
| [`counters.lms`](counters.lms) | Dump kernel protocol counters (`netstat -s`/`nstat`-lite) via `net.counters` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/counters.lms` |
| [`sockets.lms`](sockets.lms) | List listening TCP sockets and process ownership via `net.sockets` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sockets.lms` |
| [`sockets-summary.lms`](sockets-summary.lms) | Summarize socket counts by family and TCP state (`ss -s`-lite) via `net.socket_summary` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sockets-summary.lms` |
| [`scan.lms`](scan.lms) | TCP connect port scan and boolean port check via `net.scan` and `net.check` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/scan.lms` |
| [`pipe.lms`](pipe.lms) | Blocking TCP listener and client roundtrip via `net.tcp_listen` and `net.tcp_connect` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pipe.lms` |
| [`trace.lms`](trace.lms) | UDP traceroute hops and RTTs via `net.trace` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/trace.lms` |
| [`mtr.lms`](mtr.lms) | Multi-cycle per-hop loss and latency statistics via `net.mtr` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/mtr.lms` |
| [`arping.lms`](arping.lms) | Explicit-interface IPv4 ARP probe validation via `net.arping` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/arping.lms` |
| [`sys-cpu.lms`](sys-cpu.lms) | Sample aggregate and per-core CPU percentages via `sys.cpu` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-cpu.lms` |
| [`sys-mem.lms`](sys-mem.lms) | Read physical memory, swap, and PSI pressure via `sys.mem` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-mem.lms` |
| [`sys-disk.lms`](sys-disk.lms) | Measure per-device I/O byte rates, IOPS, and await via `sys.disk` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-disk.lms` |
| [`sys-top.lms`](sys-top.lms) | Rank processes by CPU, memory, or disk I/O rate via `sys.top` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-top.lms` |
| [`sys-set.lms`](sys-set.lms) | Plan a read-only `/proc/sys` sysctl change via `sys.set` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/sys-set.lms` |
| [`proc-list.lms`](proc-list.lms) | Enumerate running processes with CPU, RSS, FD, and socket counts via `proc.list` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/proc-list.lms` |
| [`proc-show.lms`](proc-show.lms) | Deep-inspect one PID (FDs, sockets, memory maps, limits) via `proc.show` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/proc-show.lms` |
| [`detect-scan.lms`](detect-scan.lms) | Scan files against embedded builtin YARA rules via `detect.scan` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/detect-scan.lms` |
| [`detect-autoruns.lms`](detect-autoruns.lms) | Enumerate Linux persistence locations and suspicion rankings via `detect.autoruns` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/detect-autoruns.lms` |
| [`detect-hashes.lms`](detect-hashes.lms) | Offline SHA-256/MD5 exact-file hash scanning via `detect.hashes_scan` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/detect-hashes.lms` |
| [`detect-quarantine.lms`](detect-quarantine.lms) | Plan a read-only file quarantine action via `detect.quarantine` | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/detect-quarantine.lms` |

See the [README](../README.md) and [CLI and DSL reference](../docs/cli-and-dsl.md) for full command and method documentation.
