# Packet-capture examples

These synthetic, offline examples use `lmdebug pcap` (`context shark: Shark`) together with [lmplot](https://github.com/lmctl-ai/lmplot) and [lmdraw](https://github.com/lmctl-ai/lmdraw). Each program builds and analyzes its own synthetic capture and writes images plus deterministic CSV.

| Picture | Example | Command |
| --- | --- | --- |
| ![dns latency](../../docs/images/pcap/dns_latency.png) | [dns latency](dns_latency.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/dns_latency.lms` |
| ![flow sankey](../../docs/images/pcap/flow_sankey.png) | [flow sankey](flow_sankey.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/flow_sankey.lms` |
| ![ip fragment reassembly](../../docs/images/pcap/ip_fragment_reassembly.png) | [ip fragment reassembly](gallery/ip_fragment_reassembly.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/gallery/ip_fragment_reassembly.lms` |
| ![quic vs tls handshake](../../docs/images/pcap/quic_vs_tls_handshake.png) | [quic vs tls handshake](gallery/quic_vs_tls_handshake.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/gallery/quic_vs_tls_handshake.lms` |
| ![tcp seqwrap and ecn](../../docs/images/pcap/tcp_seqwrap_and_ecn.png) | [tcp seqwrap and ecn](gallery/tcp_seqwrap_and_ecn.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/gallery/tcp_seqwrap_and_ecn.lms` |
| ![vlan segmentation](../../docs/images/pcap/vlan_segmentation.png) | [vlan segmentation](gallery/vlan_segmentation.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/gallery/vlan_segmentation.lms` |
| ![header anatomy](../../docs/images/pcap/header_anatomy.png) | [header anatomy](header_anatomy.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/header_anatomy.lms` |
| ![io traffic sweep](../../docs/images/pcap/io_traffic_sweep.gif)<br>![io traffic burst](../../docs/images/pcap/io_traffic_burst.png) | [io traffic sweep](io_traffic_sweep.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/io_traffic_sweep.lms` |
| ![packet loss rtt histogram](../../docs/images/pcap/packet_loss_rtt_histogram.png) | [packet loss rtt histogram](packet_loss_rtt_histogram.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/packet_loss_rtt_histogram.lms` |
| ![port scan detection](../../docs/images/pcap/port_scan_detection.png) | [port scan detection](port_scan_detection.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/port_scan_detection.lms` |
| ![protocol hierarchy](../../docs/images/pcap/protocol_hierarchy.png) | [protocol hierarchy](protocol_hierarchy.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/protocol_hierarchy.lms` |
| ![protocol sequence ladder](../../docs/images/pcap/protocol_sequence_ladder.png) | [protocol sequence ladder](protocol_sequence_ladder.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/protocol_sequence_ladder.lms` |
| ![retransmission storm](../../docs/images/pcap/retransmission_storm.png) | [retransmission storm](retransmission_storm.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/retransmission_storm.lms` |
| ![rtt distribution](../../docs/images/pcap/rtt_distribution.png) | [rtt distribution](rtt_distribution.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/rtt_distribution.lms` |
| ![slow start cwnd](../../docs/images/pcap/slow_start_cwnd.png) | [slow start cwnd](slow_start_cwnd.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/slow_start_cwnd.lms` |
| ![tcp handshake teardown](../../docs/images/pcap/tcp_handshake_teardown.png) | [tcp handshake teardown](tcp_handshake_teardown.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/tcp_handshake_teardown.lms` |
| ![tcp stevens graph](../../docs/images/pcap/tcp_stevens_graph.png) | [tcp stevens graph](tcp_stevens_graph.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/tcp_stevens_graph.lms` |
| ![tls version census](../../docs/images/pcap/tls_version_census.png) | [tls version census](tls_version_census.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/tls_version_census.lms` |
| ![top talkers topology](../../docs/images/pcap/top_talkers_topology.png) | [top talkers topology](top_talkers_topology.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/top_talkers_topology.lms` |

The I/O sweep GIF uses the original `png_gif.py` helper embedded in its script; only Python standard-library modules are needed. GIF is the Graphics Interchange Format developed by CompuServe Incorporated; [format specification](https://www.w3.org/Graphics/GIF/spec-gif89a.txt).

## Live interface inventory (unprivileged)

| Picture | Example | Command |
| --- | --- | --- |
| ![Interface up and loopback flags](../../docs/images/pcap/live/interface_inventory.png) | [Interface inventory](live/interface_inventory.lms) | `lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmdebug/main/examples/pcap/live/interface_inventory.lms` |
