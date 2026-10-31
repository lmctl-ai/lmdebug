# Manual released-binary integration

`integration.yml` is workflow_dispatch-only. It runs on Linux x64/arm64,
macOS Intel (`macos-15-intel`), macOS arm64 (`macos-15`) and Windows x64.
No private implementation is built or copied into this public repository.

The default is lmdebug **v0.1.36** with examples from its matching public git
tag. Current main changed host option spellings after that release; selecting
`examples_ref=main` requires a separately reviewed platform manifest and a matching
released protocol; it cannot silently reuse the v0.1.36 expected set.
The harness never rewrites host command flags. A versioned, checked Python-only
compatibility patch fixes pipe supervision and raw-byte hashing for the released
examples; reports record the patch and before/after helper hashes.

Released hosts and exact auxiliary versions are in `scripts/integration-hosts.json`.
Downloads require a GitHub release SHA-256 digest or matching SHA256SUMS entry;
lmconn archives yield only their selected executable. lmmock is installed through
`lmscript install github:lmctl-ai/lmmock@v0.1.36`, with an independent hash check.
Two compilers are necessary: lmdebug's release reads bytecode v5 (lmscript
0.2.426), while lmmock's release reads v6 (lmscript 0.2.448). The workflow installs
both explicitly. Setup Python provides the `python3` alias used by examples on
Windows; runner OpenSSL supplies ephemeral TLS test certificates. Version and
asset hashes are recorded with the report.

Every platform-supported example must execute successfully.
`scripts/integration-platforms.json` lists all 50 examples and the exact native
expected set: Linux runs 50; Windows runs 29 and explicitly skips 21 Linux-only
examples. Unknown refs or added/unreviewed examples fail closed. Every skip has
a capability and reason in the JSON report and workflow summary. Historical chapter files that
only call savedsl are followed by actual released-host bytecode execution;
files that execute their own programs retain their orchestration. Declared
`#|` expected outputs must occur. The harness supplies a benign MIT test-marker
input at the historical scan path and records its hash; embedded rule code
remains in the product. No skipped/compile-only case is counted as an E2E pass.

The additional traffic gate uses only loopback:
- released lmmock handlers and lmconn send/verify 12 distinct sentinel POSTs;
- released lmdebug iperf3 transfers for one second, capped at 10 Mbit/s, and
  must report nonzero bytes; its server binds only 127.0.0.1;
- lmdebug collects valid network sampling observations during the test;
- lmdebug live acquisition (Linux), tcpdump (macOS), or pktmon (Windows)
  captures the loopback mock TCP port; lmdebug's
  offline analyzer must find packet/byte counts and the actual request sentinel
  in a reconstructed TCP stream. External backends are labeled as external
  capture plus analysis, not as native Windows live acquisition.

POSIX capture uses passwordless sudo on hosted runners. Windows requires the
real HTTP sentinel roundtrips, nonzero iperf bytes, valid sampling results, and
all supported offline-PCAP examples. Native live capture is unsupported in the
released Windows host (no Npcap). In run 41240976973, pktmon captured only a
188-byte pcapng header for localhost despite successful real HTTP/iperf traffic.
Its capture-only check is now an explicit manifest SKIP, never described as a
successful packet capture; Linux capture and sentinel reassembly remain required.
The traffic report separates that skip from the supported checks that passed.
Sampling asserts valid metric observations; it does not claim Windows aggregate
adapter counters include loopback bytes (they were zero in the diagnostic run).

Windows failure classification from run 41240976973:

| Examples | Classification and action |
| --- | --- |
| detect-autoruns/quarantine/scan, detect-hashes | Linux detection backend; explicit SKIP |
| dns-lookup/query, ethtool, neigh, rule, scan, arping/mtr/trace | Linux network backend; explicit SKIP |
| proc-list/show, sys-cpu/disk/mem/set/top | Linux proc/sys backend; explicit SKIP |
| pcap/live/interface_inventory | Windows live interface enumeration unsupported; explicit SKIP |
| correlation/https-packets-offline | Supported; helper now hashes raw UTF-8 bytes without CRLF translation |
| segment/local-https-timing, segment/local-tcp-timing | Supported; bounded Windows pipe readers replace POSIX select/killpg |
| Real loopback traffic capture | Unsupported native backend and header-only pktmon evidence; capture-only SKIP |

Passing an error-as-data branch does not establish a backend is supported:
Linux-only examples that happened to return zero on Windows also explicitly skip.
The observed failures did not identify a defect in an advertised Windows backend;
product functionality is unchanged. Windows helper fixes still need native CI.

Known limits (2026-10-31): v0.1.36 publishes no macOS lmdebug assets, so both
macOS legs explicitly report SKIP (zero examples passed), with the missing asset
and Apple-port reason in their JSON reports and job summaries. The workflow
passes `--skip-unsupported-macos`; standalone runs still fail closed by default.
Only an absent primary macOS asset may skip: failed downloads, checksum proofs,
auxiliary assets and execution errors remain failures. Once native assets exist,
the Apple expected set must be reviewed before native coverage can be claimed. The private source also
needs an Apple CMake/backend/dependency port before native Mac build/package/
smoke can be claimed. The updated supported Windows subset needs an owner-dispatched native rerun. The report includes actual `lmdebug caps` and per-example output; successful
error-as-data examples do not establish native support for unsupported domains.
Python supervisor portability failures or release/content drift remain failures.
Linux x64 locally passed all 50 released examples and the real traffic gate.

Run `./test.sh` for offline runner contracts. For a real local run, install
0.2.426 and 0.2.448 into separate npm prefixes, then pass their executable paths
as `--compiler` and `--mock-compiler` to `scripts/integration-run.py`; use
`--sudo-capture` on POSIX. `--only` is a development filter; `--skip-traffic`
produces a failed/incomplete run. Fresh work directories are required.
Reports go to `out/integration-report.json`; failed native jobs upload the
report and generated capture/example witnesses. Tools/cache binaries are excluded.
