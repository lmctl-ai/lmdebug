# Third-Party Notices

## libpcap

Linux live capture uses the statically linked libpcap 1.10.5 release from
https://www.tcpdump.org/ (pinned by `libpcap.lock` and fetched by
`scripts/sync-libpcap.sh`). The upstream `third_party/libpcap/LICENSE` is BSD:

```
License: BSD

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
```

The static build disables remote capture and optional libnl, D-Bus, Bluetooth,
RDMA, USB, netfilter, netmap and other transports. macOS uses its system
libpcap/BPF framework; Windows ships no Npcap and reports live capture as
unsupported. libpcap is used only by the live-capture adapter; the original
offline parser remains the lmdebug-owned implementation.

### libpcap parser/scanner generation

The shipped parser is generated with Berkeley Yacc 2.0 (20220114), whose
parser skeleton is public domain; no Bison/GPL skeleton is included. Source:
https://invisible-island.net/byacc/ . The scanner is generated with flex 2.6.4;
its upstream COPYING explicitly places no license restriction on generated
scanners: https://github.com/westes/flex/blob/v2.6.4/COPYING . These generators
are not shipped and are not needed for ordinary builds.

The original libpcap grammar/scanner retain their UC Berkeley notices
(the scanner also credits copyright 1997, The Regents of the University of
California, in addition to the grammar copyright years below):

```
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */
```

This product includes software developed by the University of California,
Lawrence Berkeley Laboratory and its contributors.

## iputils

This repository builds against, and includes verbatim source files from,
**iputils** — a set of small useful utilities for Linux networking.

- Upstream: https://github.com/iputils/iputils
- Version: 20250605, pinned in `iputils.lock`
- Copyright (C) various authors; see the vendored `LICENSE` file at
  `third_party/iputils/LICENSE` after running `scripts/sync-iputils.sh`
- Per-tool licenses (from the upstream LICENSE file):
  - `ping`: **BSD-3-Clause**
  - `tracepath`: **GPL-2.0-or-later**, historical only; no longer compiled
  - (`arping`: GPL-2.0-or-later and `clockdiff`: BSD-3-Clause are vendored
    with the tarball but not compiled into lmdebug)

Only the BSD-3-Clause ping sources and public-domain MD5 are compiled from
iputils. The vendored `tracepath.c` and `iputils_common.c` are excluded from
the build. The few common helpers needed by ping are original lmdebug code
in `cpp/iputilsshim/iputils_common.c/.h`; the native JSON `tracepath` alias
uses the original lmdebug trace/PMTU engine. No upstream tracepath code was
copied into those replacements. lmdebug-authored code is proprietary under
`LICENSE`; third-party files retain their upstream licenses.

### Previously shipped tracepath

The GPL-2.0-or-later iputils tracepath engine was included in builds up to
2026-10-25, before this removal commit. It is no longer included in builds
from this commit onward. Source for the previously shipped engine is available
from the exact pinned upstream release:

- https://github.com/iputils/iputils/releases/download/20250605/iputils-20250605.tar.gz
- SHA-256: `475c643e5f55b302286267b97d3ce0f47ca3489ced8aa0401b1eeb1e68228d6b`

The full iputils tarball remains available through `scripts/sync-iputils.sh`
for source/license inspection; its GPL tools are not linked into lmdebug.

## iperf3

This repository builds against, and includes verbatim source files from,
**iperf3** — the standard TCP/UDP/SCTP network throughput measurement tool.

- Upstream: https://github.com/esnet/iperf (tarball from https://downloads.es.net/pub/iperf/)
- Version: 3.22, pinned in `iperf3.lock` and synced by `scripts/sync-iperf3.sh`
- Copyright (c) 2014-2023 The Regents of the University of California, through
  Lawrence Berkeley National Laboratory; see the vendored `LICENSE` file at
  `third_party/iperf3/LICENSE` after running `scripts/sync-iperf3.sh`
- License: **BSD-3-Clause** — the vendored LICENSE states the three classic
  BSD redistribution conditions (retain copyright notice, reproduce in
  documentation, no endorsement without permission) and: "THIS SOFTWARE IS
  PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND [...]"
  (BSD-style disclaimer), preceded by the U.S. Dept. of Energy notice.

lmdebug compiles the iperf3 engine (with its `main` renamed) into the `lmdebug
iperf3` subcommand, built without OpenSSL authentication and without SCTP,
matching iperf's own configure defaults; `cpp/iperf3shim/iperf_config.h` and
`cpp/iperf3shim/version.h` stand in for the headers autotools would generate.

## YARA (libyara)

This repository builds against, and includes verbatim source files from,
**YARA (`libyara`)** — the pattern-matching swiss knife for malware researchers.

- Upstream: https://github.com/VirusTotal/yara
- Version: 4.5.2, pinned in `yara.lock` and synced by `scripts/sync-yara.sh`
- Copyright (c) 2007-2024 The YARA Authors. All Rights Reserved; see the
  vendored `COPYING` file at `third_party/yara/COPYING` after running
  `scripts/sync-yara.sh`
- License: **BSD-3-Clause** — `libyara` carries the standard 3-clause BSD
  redistribution conditions and disclaimer. `libyara` also includes embedded
  TLSH (`libyara/tlshc/`, Trend Micro Open Source License / Apache-2.0
  compatible BSD-style terms; see `third_party/yara/libyara/tlshc/`).

lmdebug compiles `libyara` as a static library (`yara_static`) for the
`lmdebug detect scan` engine, built without OpenSSL (`HAVE_LIBCRYPTO` disabled),
without `cuckoo` (`libjansson`), and without `magic` (`libmagic`). Only
first-party lmdebug-authored YARA rules (`rules/builtin.yar`) are embedded in
the binary; no third-party or community rule sets are bundled.

## lmcode-cpp SDK

`cpp/dslvm.hpp`, `cpp/stdlib/*.hpp`, `cpp/std/lmcode-std.schema.json` and
`scripts/merge-std.py` are vendored from lmcode-cpp (MIT License, Lattice
Systems LLC), pinned by `sdk.lock` and synced by `scripts/sync-sdk.sh`.

### lmcode-cpp MIT notice

MIT License

Copyright (c) 2026 Lattice Systems LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Original packet-capture domain

`cpp/pcap/` imports the user's own clean-room lmshark implementation, copyright
(c) 2026 Lattice Systems LLC. The original MIT notice is retained in
`cpp/pcap/LICENSE.MIT`; the root lmdebug license remains proprietary. See
`docs/design/pcap-provenance.md` for the source snapshot and supplied similarity
audit. No Wireshark, epan, wiretap, libpcap, tcpdump, GPL or LGPL packet-analysis
code or library is included or linked by this addition. The already documented
system glibc linkage is unchanged.
