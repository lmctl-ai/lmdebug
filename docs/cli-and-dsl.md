# lmdebug CLI and DSL Reference

`lmdebug` combines classic Linux network, system, process, packet-capture, and detection tools with structured JSON output and an embedded `lmscript` DSL host in one self-contained executable.

## CLI subcommands

```text
lmdebug --version
lmdebug caps                                    # platform, effective privileges, and supported commands
lmdebug sys cpu [--interval MS]                  # CPU deltas and per-core percentages
lmdebug sys mem                                  # memory, swap, and pressure
lmdebug sys set KEY=VALUE [--apply] [--force] [--if-match ID] [--audit-file PATH]
lmdebug sys disk [--interval MS] [--count N]     # per-device I/O rates, await, and pressure
lmdebug sys top [--interval MS] [--count N] [--top N] [--sort cpu|mem|disk]
lmdebug --dsl-schema [--json]
lmdebug --dsl-signatures
lmdebug ping HOST [iputils ping options]        # the real iputils ping engine
lmdebug tracepath HOST [-m hops] [-l len] [-n]  # native trace --pmtu alias (JSON)
lmdebug iperf3 [iperf3 options]                 # the real iperf3 engine (client/server)
lmdebug dns HOST                                # resolve addresses (nslookup-lite)
lmdebug dig NAME [TYPE] [@server]               # DNS query as JSON (dig-lite)
lmdebug ifaddrs                                 # interfaces + addresses as JSON (ip addr-lite)
lmdebug route                                   # routing tables as JSON (ip route-lite)
lmdebug rule                                    # policy routing rules as JSON (ip rule-lite)
lmdebug neigh                                   # neighbor table as JSON (ip neigh-lite)
lmdebug link                                    # link devices + RX/TX counters as JSON (ip -s link-lite)
lmdebug link set IFACE [up|down] [mtu N] [--apply] [--force] [--if-match ID] [--audit-file PATH]
lmdebug ethtool IFACE [-i|--driver-info|-S|--statistics]  # ethtool-lite link settings/driver/statistics as JSON
lmdebug counters                                # kernel networking counters as JSON (netstat -s/nstat-lite)
lmdebug sockets [tcp|udp|unix] [--listen] [--summary]  # socket tables as JSON (netstat/lsof -i-lite, ss -s-lite)
lmdebug trace HOST [maxttl] [--pmtu] [-l len]   # UDP-probe traceroute as JSON (traceroute-lite)
lmdebug mtr HOST [--cycles N] [--interval MS] [--timeout MS] [--max-ttl N] [--live]  # repeated per-hop loss/latency report as JSON
lmdebug arping IFACE HOST [--count N] [--interval MS] [--timeout MS]  # IPv4 ARP reachability on one Ethernet link
lmdebug scan HOST [--ports SPEC] [--timeout MS] [--concurrency N]  # TCP connect port scanner as JSON (nmap-lite)
lmdebug pipe HOST PORT | --listen PORT [--forever]  # TCP stdio bridge (nc-lite)
lmdebug proc [list] [--user U] [--name TEXT] [--pid PID] [--sort pid|cpu|mem|name] [--top N] [--fds] [--net]  # process table as JSON (ps/lsof-lite)
lmdebug proc show PID [--fds] [--net] [--maps]  # deep inspection of one PID as JSON (or `lmdebug proc PID ...`)
lmdebug proc kill PID [--signal SIG] [--apply] [--force] [--if-match ID] [--audit-file PATH]  # plan or send a signal via the change framework
lmdebug detect hashes import PATH [--db PATH] [--format auto|plain|malwarebazaar-sha256|threatfox-ioc] [--source NAME] [--apply]
lmdebug detect hashes scan PATH [--db PATH] [--recursive]
lmdebug detect hashes status [--db PATH]
lmdebug detect quarantine PATH [--quarantine-dir DIR] [--rule NAME:SEVERITY] [--apply] [--force]
lmdebug detect restore ID [--quarantine-dir DIR] [--apply] [--force]
lmdebug detect scan PATH [--rules PATH] [--max-size MB]  # YARA file/directory scan with builtin or custom rules as JSON
lmdebug detect autoruns [--root DIR] [--json]  # Linux persistence location enumeration as JSON
lmdebug pcap [--version | --dsl-schema [--json] | --dsl-signatures | [--dry-run] --dsl FILE]
lmdebug [--dry-run] [--plan-format json|text] [--dry-loop-limit N] --dsl FILE [FILE ...]
```

## Capabilities (`lmdebug caps` / `lmdebug.caps_json()`)

Call `lmdebug caps` first to discover this build's version, OS, architecture, effective privileges, and public command table. On Linux, `root` reflects the effective UID and `cap_net_raw`/`cap_net_admin` reflect effective capability bits. Command `supported` describes platform availability, not whether the current user has permission or an interface supports every query. `needs` lists privileges for restricted operations (for example, `link.set` needs `cap_net_admin`; listing links remains unprivileged). `mutating_verbs` contains full registered action names such as `link.set`, `sys.set`, `proc.kill`, `detect.hash_import`, `detect.quarantine`, and `detect.restore`. The DSL exposes the same JSON document as `lmdebug.caps_json()` on the `lmdebug` (`Meta`) context.

## System domain (`sys`)

- `sys cpu` (`sys.cpu()`, `sys.cpu(interval_ms)`) samples `/proc/stat` twice (default 500 ms, `--interval` 50–10000 ms) and reports `cpu_count`, per-core rows (`CpuResult.cores()`), and aggregate user/system/iowait/idle percentages.
- `sys mem` (`sys.mem()`) reports `/proc/meminfo` total/free/available bytes, used percentage, swap totals/utilization, and PSI `some`/`full` avg10 values when exposed (or `-1` when unavailable).
- `sys disk` (`sys.disk()`, `sys.disk(interval_ms[, count])`) reports completed reads/writes, 512-byte-sector counters, in-flight I/O, byte rates, IOPS, read/write await, and utilization per top-level block device (`DiskResult.disks()`).
- `sys top` (`sys.top()`, `sys.top(interval_ms, limit[, sort[, count]])`) ranks processes by CPU capacity percentage (`0..100`), RSS, or combined disk I/O rate (`--sort cpu|mem|disk`, `--top 0..100` default `10`).
- `sys set KEY=VALUE` (`sys.set(key, value)`) plans a persistent, readable `/proc/sys` control change through the mutation framework (`sys.set`). All `kernel.*` keys and `vm.swappiness` outside `0..100` require `--apply --force`. Write-only one-shot controls (`vm.drop_caches`, `vm.compact_memory`) are refused with exit `5`.

## Networking domain (`net`)

- `dns` (`net.dns_lookup(host)`) resolves IPv4/IPv6 addresses via `getaddrinfo`.
- `dig` (`net.dns_query(name, qtype, server)`) sends an RFC 1035 UDP DNS query (3 s timeout) and returns `rcode` plus `{name, type, ttl, data}` answer records.
- `ifaddrs` (`net.interfaces()`) lists interfaces carrying addresses (`name`, `addr`, `netmask`, `family`, `mtu`, `up`, `loopback`).
- `link` (`net.links()`) dumps every link device over rtnetlink with 64-bit RX/TX byte, packet, error, and drop counters.
- `link set IFACE [up|down] [mtu N]` (`net.link_set(iface, state, mtu)`) plans or applies administrative state (`IFF_UP`) and/or MTU (`68..65535`) changes over rtnetlink (`link.set`, requires `cap_net_admin`, requires `--force` when `mtu < 576`).
- `ethtool` (`net.ethtool_link(iface)`, `net.ethtool_driver(iface)`, `net.ethtool_stats(iface)`) queries link speed/duplex/autoneg/port/carrier, driver/firmware/bus metadata, and kernel NIC statistics via `SIOCETHTOOL`.
- `route` (`net.routes()`) dumps all kernel IPv4 and IPv6 routing tables over rtnetlink (`dest`, `via`, `dev`, `proto`, `scope`, `metric`, `table`, `prefsrc`).
- `rule` (`net.rules()`) dumps policy routing rules over rtnetlink (`pref`, `family`, `table`, `action`, `from`, `to`, `fwmark`, `iif`, `oif`, `goto_target`).
- `neigh` (`net.neighbors()`) dumps the ARP/NDP neighbor table over rtnetlink (`ip`, `dev`, `state`, `mac`, `family`, `router`, `proxy`).
- `counters` (`net.counters()`) reads `/proc/net/{snmp,netstat,snmp6}` protocol counters as `Section.Field` / `Ip6*` pairs.
- `sockets` (`net.sockets(proto, listen_only)` and `net.socket_summary(proto)`) inspects `/proc/net/{tcp,tcp6,udp,udp6,unix}` tables with `/proc/<pid>/fd` ownership attribution and `ss -s`-style aggregates.
- `trace` (`net.trace(host, max_ttl)`) and `tracepath` (`trace --pmtu`) send UDP probes and collect ICMP time-exceeded/unreachable/fragmentation-needed replies (IPv4, requires root or `CAP_NET_RAW`).
- `mtr` (`net.mtr(host, cycles[, interval_ms, max_ttl])`) runs repeated UDP probe bursts and reports per-hop loss, last/min/avg/max/stdev/jitter latency, and responder hosts (IPv4, requires root or `CAP_NET_RAW`).
- `arping` (`net.arping(iface, host, count, interval_ms, timeout_ms)`) sends bounded IPv4 ARP requests on an explicitly selected Ethernet interface (requires root or `CAP_NET_RAW`).
- `scan` (`net.scan(host, ports_spec)` and `net.check(host, port)`) performs parallel non-blocking TCP connect port scans (`open`, `closed`, `filtered`) without requiring root privileges.
- `pipe` (`net.tcp_connect(host, port)` and `net.tcp_listen(port)`) provides a binary-safe TCP stdio bridge on the CLI and blocking `TcpConn` / `TcpListener` objects in the DSL.

## Process domain (`proc`)

- `proc [list]` (`proc.list()`) enumerates `/proc/<pid>` processes with `pid`, `ppid`, `user`, `name`, `state`, `cpu_pct`, `rss_bytes`, `vsz_bytes`, `fd_count`, `exe`, `cmdline`, and `net_count`.
- `proc show PID` (`proc.show(pid)`) inspects one process in depth, including UID/GID/groups, threads, OOM score, environment (`environ_denied` when restricted), resource limits (`ProcLimitList`), open file descriptors (`ProcFdList`, up to 256), sockets (`ProcNetList`), and memory mappings (`ProcMapList`, first 200 VMAs).
- `proc kill PID [--signal SIG]` (`proc.kill(pid, signal)`) plans or delivers a signal via `pidfd_send_signal`, pinning `pid`, `start_time`, and `starttime_ticks` against PID reuse (`SIGKILL` and kernel threads require `--force`; PID 1 and `lmdebug` itself are refused).

## Detection domain (`detect`)

- `detect scan PATH [--rules PATH] [--max-size MB]` (`detect.scan(path[, ...])`) scans a file or directory tree in deterministic lexicographical order using embedded static `libyara` and builtin rules (or custom `.yar`/`.yara` rules), reporting matches, string offsets, SHA-256 digests, and structured skip reasons.
- `detect autoruns [--root DIR]` (`detect.autoruns([root])`) enumerates Linux persistence locations (systemd system/user units, cron, shell rc files, `/etc/ld.so.preload`, `/etc/ld.so.conf*`, `/etc/rc.local`) with deterministic suspicion rankings (`none`, `low`, `medium`, `high`).
- `detect hashes import|scan|status` (`detect.hash_import(path[, db])`, `detect.hashes_scan(path[, db[, recursive]])`) maintains an offline sorted-flat SHA-256/MD5 signature store (`LMHASH01`) supporting plain hex lists, MalwareBazaar CSV, and ThreatFox IOC CSV feeds.
- `detect quarantine PATH` and `detect restore ID` (`detect.quarantine(path[, dir])`, `detect.restore(id[, dir])`) move files into a `0700` quarantine store (`0400` payload + `0600` JSON sidecar with SHA-256 and original ownership/mode) and restore them with hash verification under the mutation framework.

## Packet capture domain (`lmdebug pcap` / `context shark: Shark`)

`lmdebug pcap` reads and writes pcap/pcapng files, builds synthetic packets, dissects protocols, reconstructs flows and TCP streams, evaluates display and cBPF filters, and exports statistics, CSV, and JSON. Linux live capture (`shark.interfaces()`, `shark.compile_filter(expr, linktype)`, `shark.live(iface, max_packets, duration_sec, snaplen, promisc, immediate, bpf)`) uses statically linked BSD `libpcap` (requires root or `CAP_NET_RAW` for `shark.live`); offline analysis and cBPF compilation require no special privileges.

## Mutation framework and dry-run planning

Mutating verbs (`link.set`, `sys.set`, `proc.kill`, `detect.hash_import`, `detect.quarantine`, `detect.restore`) are dry-run by default:

- Without `--apply`, they read current state and emit a JSON plan (`plan_id`, `before`, predicted `after`, `diff`, `undo`, `warnings`, `needs`, `needs_force`) without modifying the system.
- `--apply` re-reads state, writes an intent record to the append-only JSONL audit log, performs the mutation, verifies the post-state, and writes an outcome audit record.
- `--force` unlocks destructive or out-of-range operations (`needs_force: true`).
- `--if-match sha256:<64hex>` requires the fresh `plan_id` at apply time to match the approved plan ID (exiting `6` on drift).
- `lmdebug --dry-run [--plan-format json|text] [--dry-loop-limit N] --dsl FILE.dslb` runs DSL bytecode in host-effect dry-run mode and emits the `lmscript` host-effect plan envelope (`lmscript.host_plan.v1`) without mutating the system.
