#!/usr/bin/env python3
"""HTTPS packet-to-TLS-flight correlation engine, live capture supervisor, and fixture generator.

Implements Design Slice 3 of docs/design/lmssl-correlation-examples.md:
- Offline correlation of lmdebug pcap packet tables with lmssl OpenSSL SSL_trace records
- Honest TLS 1.3 flight attribution (exact for TCP handshake & unambiguous visible hellos;
  flight-level candidate sets for encrypted post-ServerHello handshake and application data;
  never fabricated decrypted per-packet claims)
- Separate time axes (application steady_clock ssl.monotonic_us() vs pcap capture timestamps)
- Bounded live capture supervisor (--live and --loopback-self-test)
- Reproducible offline fixture generation (--generate-fixture) and 8-case regression suite (--self-test)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from typing import Any

FORMAT_VERSION = 1
TRACE_PARSER_VERSION = "openssl-ssl-trace-v1"
HRR_RANDOM_HEX = "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"


def seq_add(seq: int, length: int) -> int:
    return (int(seq) + int(length)) & 0xFFFFFFFF


def seq_diff(a: int, b: int) -> int:
    return ((int(a) - int(b) + 0x80000000) & 0xFFFFFFFF) - 0x80000000


def seq_le(a: int, b: int) -> bool:
    return seq_diff(a, b) <= 0


def seq_lt(a: int, b: int) -> bool:
    return seq_diff(a, b) < 0


def fmt_seq_range(start: int | None, length: int | None) -> str:
    if start is None or length is None:
        return ""
    s = int(start) & 0xFFFFFFFF
    e = seq_add(s, max(0, int(length)))
    return f"{s}..{e}"


def fmt_ms(us: int | None) -> str:
    if us is None:
        return "n/a"
    return f"{us / 1000.0:.3f} ms"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_https_url(raw_url: str) -> dict[str, Any]:
    """Validate target URL per design doc §2.1 step 1."""
    if not raw_url or any( ch in raw_url for ch in ("\r", "\n", "\t", " ", "\x00") ):
        raise ValueError(f"Invalid URL (contains whitespace or control characters): {raw_url!r}")
    for ch in raw_url:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError(f"Invalid URL (control character 0x{ord(ch):02x})")
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Only https:// URLs are supported (got scheme {parsed.scheme!r})")
    if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
        raise ValueError("URLs with userinfo/credentials are refused")
    if not parsed.hostname:
        raise ValueError(f"URL is missing hostname: {raw_url!r}")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError(f"Invalid URL port: {exc}") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range: {port}")

    host = parsed.hostname
    is_ipv6_literal = ":" in host
    is_ip_literal = False
    try:
        ipaddress.ip_address(host)
        is_ip_literal = True
    except ValueError:
        pass

    path = parsed.path if parsed.path else "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    if any(ch in path for ch in ("\r", "\n", "\x00")):
        raise ValueError("Invalid characters in URL path/query")

    host_brackets = f"[{host}]" if is_ipv6_literal else host
    host_header = host_brackets if port == 443 else f"{host_brackets}:{port}"
    sanitized_url = f"https://{host_header}{path}"
    return {
        "sanitized_url": sanitized_url,
        "host": host,
        "port": port,
        "path": path,
        "host_header": host_header,
        "is_ipv6_literal": is_ipv6_literal,
        "is_ip_literal": is_ip_literal,
    }


def parse_ssl_trace(trace_text: str, handshake_snapshot: str = "") -> list[dict[str, Any]]:
    """Parse OpenSSL SSL_trace output into an ordered list of trace events.

    Preserves message order, record boundaries (detecting coalesced messages in a
    single TLS record and handshake messages split across records), and unknown records.
    """
    records: list[dict[str, Any]] = []
    block_re = re.compile(r"^(Sent|Received) TLS Record\r?\n", re.MULTILINE)
    matches = list(block_re.finditer(trace_text))
    hs_cutoff = len(handshake_snapshot) if handshake_snapshot else -1

    hs_msg_re = re.compile(
        r"^\s{4}(ClientHello|ServerHello|HelloRetryRequest|EncryptedExtensions|"
        r"CertificateRequest|Certificate|CertificateVerify|Finished|"
        r"NewSessionTicket|KeyUpdate),\s*Length=(\d+)\s*$"
    )
    alert_re = re.compile(r"^\s{4}Level=([A-Za-z0-9_]+)\((\d+)\),\s*description=([A-Za-z0-9_ ]+)\((\d+)\)\s*$")

    for idx, m in enumerate(matches):
        dir_word = m.group(1)
        direction = "C->S" if dir_word == "Sent" else "S->C"
        start_pos = m.start()
        end_pos = matches[idx + 1].start() if idx + 1 < len(matches) else len(trace_text)
        block = trace_text[start_pos:end_pos]
        in_initial_handshake = (hs_cutoff < 0) or (start_pos < hs_cutoff)

        ver_m = re.search(r"^\s*Version\s*=\s*(.+)$", block, re.MULTILINE)
        ct_m = re.search(r"^\s*Content Type\s*=\s*([A-Za-z0-9_]+)\s*\((\d+)\)", block, re.MULTILINE)
        len_m = re.search(r"^\s*Length\s*=\s*(\d+)", block, re.MULTILINE)
        ict_m = re.search(r"^\s*Inner Content Type\s*=\s*([A-Za-z0-9_]+)\s*\((\d+)\)", block, re.MULTILINE)

        outer_ct = ct_m.group(1) if ct_m else "Unknown"
        outer_len = int(len_m.group(1)) if len_m else None
        inner_ct = ict_m.group(1) if ict_m else None
        effective_ct = inner_ct or outer_ct
        encrypted_record = (outer_ct == "ApplicationData" and inner_ct is not None)

        msg_items: list[dict[str, Any]] = []
        lines = block.splitlines()
        in_cert_pem = False
        for line in lines:
            if "-----BEGIN CERTIFICATE-----" in line:
                in_cert_pem = True
                continue
            if "-----END CERTIFICATE-----" in line:
                in_cert_pem = False
                continue
            if in_cert_pem:
                continue
            hm = hs_msg_re.match(line)
            if hm:
                msg_name = hm.group(1)
                msg_len = int(hm.group(2))
                if msg_name == "ServerHello" and HRR_RANDOM_HEX in block.upper():
                    msg_name = "HelloRetryRequest"
                msg_items.append({
                    "kind": "handshake",
                    "label": msg_name,
                    "trace_len": msg_len,
                })
                continue
            if line.strip() == "change_cipher_spec (1)":
                msg_items.append({
                    "kind": "ccs",
                    "label": "ChangeCipherSpec",
                    "trace_len": 1,
                })
                continue
            am = alert_re.match(line)
            if am:
                desc = am.group(3).strip()
                label = "TLS close_notify" if desc == "close notify" else f"TLS Alert ({desc})"
                msg_items.append({
                    "kind": "alert",
                    "label": label,
                    "trace_len": 2,
                })

        if not msg_items:
            if effective_ct == "ApplicationData":
                msg_items.append({
                    "kind": "appdata",
                    "label": "TLS ApplicationData",
                    "trace_len": outer_len,
                })
            else:
                msg_items.append({
                    "kind": "unknown",
                    "label": f"UnknownTraceRecord({effective_ct})",
                    "trace_len": outer_len,
                })

        coalesced_in_record = len(msg_items) > 1
        for item in msg_items:
            split_record = False
            if (
                item["kind"] == "handshake"
                and item["trace_len"] is not None
                and outer_len is not None
                and (item["trace_len"] + 4) > outer_len
            ):
                split_record = True
            records.append({
                "record_index": idx,
                "direction": direction,
                "outer_content_type": outer_ct,
                "inner_content_type": inner_ct,
                "effective_content_type": effective_ct,
                "outer_record_len": outer_len,
                "encrypted_record": encrypted_record,
                "in_initial_handshake": in_initial_handshake,
                "coalesced_in_record": coalesced_in_record,
                "split_across_records": split_record,
                "kind": item["kind"],
                "label": item["label"],
                "trace_len": item["trace_len"],
                "raw_version": ver_m.group(1).strip() if ver_m else "",
            })
    return records


def parse_endpoint(ep: str) -> tuple[str, int]:
    """Parse '1.2.3.4:443' or '[::1]:443' or '::1:443' into (ip, port)."""
    ep = ep.strip()
    if ep.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", ep)
        if not m:
            raise ValueError(f"Malformed bracketed endpoint: {ep!r}")
        return m.group(1), int(m.group(2))
    idx = ep.rfind(":")
    if idx <= 0:
        raise ValueError(f"Malformed endpoint: {ep!r}")
    return ep[:idx], int(ep[idx + 1:])


def load_dissected_fields_csv(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            pkt_no = int(row["frame.number"])
            src_ip = row.get("ip.src") or row.get("ipv6.src") or ""
            dst_ip = row.get("ip.dst") or row.get("ipv6.dst") or ""
            src_port = int(row["tcp.srcport"]) if row.get("tcp.srcport") else 0
            dst_port = int(row["tcp.dstport"]) if row.get("tcp.dstport") else 0
            ts_ns = int(row["frame.time_epoch_ns"]) if row.get("frame.time_epoch_ns") else int(round(float(row.get("frame.time") or "0") * 1e9))
            tcp_seq = int(row["tcp.seq"]) if row.get("tcp.seq") else None
            tcp_ack = int(row["tcp.ack"]) if row.get("tcp.ack") else None
            tcp_len = int(row["tcp.len"]) if row.get("tcp.len") else 0
            frame_len = int(row["frame.len"]) if row.get("frame.len") else 0
            cap_len = int(row["frame.cap_len"]) if row.get("frame.cap_len") else frame_len
            flags_str = (row.get("tcp.flags") or "").strip()
            flags_set = {f.strip().upper() for f in flags_str.split(",") if f.strip()}
            retrans = (row.get("tcp.analysis.retransmission") or "").strip().lower() == "true"
            tls_hs_type = (row.get("tls.handshake.type") or "").strip()
            tls_ver = (row.get("tls.version") or "").strip()
            tls_sni = (row.get("tls.sni") or "").strip()
            tls_alpn = (row.get("tls.alpn") or "").strip()
            tls_cs = (row.get("tls.cipher_suite") or "").strip()
            info = (row.get("frame.info") or "").strip()
            rows.append({
                "dsl_index": pkt_no - 1,
                "packet_id": pkt_no,
                "ts_ns": ts_ns,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "seq": tcp_seq,
                "ack": tcp_ack,
                "flags": flags_str,
                "flags_set": flags_set,
                "tcp_len": tcp_len,
                "frame_len": frame_len,
                "cap_len": cap_len,
                "retransmission": retrans,
                "tls_hs_type": tls_hs_type,
                "tls_version": tls_ver,
                "tls_sni": tls_sni,
                "tls_alpn": tls_alpn,
                "tls_cipher_suite": tls_cs,
                "info": info,
            })
    return rows


def correlate_exchange(
    dissected_rows: list[dict[str, Any]],
    trace_text: str,
    manifest: dict[str, Any],
    handshake_trace_text: str = "",
) -> dict[str, Any]:
    """Correlate dissected TCP/TLS packets with OpenSSL SSL_trace and application timings."""
    tup = manifest["tuple"]
    client_ip = tup["client_ip"]
    client_port = int(tup["client_port"])
    server_ip = tup["server_ip"]
    server_port = int(tup["server_port"])

    tls_meta = manifest.get("tls", {})
    negotiated_ver = tls_meta.get("version", "TLSv1.3")
    if negotiated_ver != "TLSv1.3":
        return {
            "ok": False,
            "status": "unsupported_profile",
            "error": (
                f"Negotiated TLS version {negotiated_ver!r} is outside the TLS 1.3 packet-correlation "
                "profile; refusing to apply TLS 1.3 flight labels."
            ),
            "packets": [],
            "steps": [],
            "completeness": {"complete_handshake": False},
        }

    matched: list[dict[str, Any]] = []
    ignored_count = 0
    for r in dissected_rows:
        if (
            r["src_ip"] == client_ip
            and r["src_port"] == client_port
            and r["dst_ip"] == server_ip
            and r["dst_port"] == server_port
        ):
            rc = dict(r)
            rc["direction"] = "C->S"
            matched.append(rc)
        elif (
            r["src_ip"] == server_ip
            and r["src_port"] == server_port
            and r["dst_ip"] == client_ip
            and r["dst_port"] == client_port
        ):
            rc = dict(r)
            rc["direction"] = "S->C"
            matched.append(rc)
        else:
            ignored_count += 1

    if not matched:
        return {
            "ok": False,
            "status": "tuple_mismatch",
            "error": (
                f"Zero packets matched tuple {client_ip}:{client_port} <-> {server_ip}:{server_port} "
                f"(ignored {ignored_count} non-matching packets)."
            ),
            "packets": [],
            "steps": [],
            "completeness": {
                "ignored_tuple_packets": ignored_count,
                "matched_packets": 0,
                "complete_handshake": False,
            },
        }

    # Check if any visible ServerHello in packets negotiated non-TLS 1.3
    for p in matched:
        if p["tls_hs_type"] == "2" and p["tls_version"] and p["tls_version"] != "TLS 1.3":
            return {
                "ok": False,
                "status": "unsupported_profile",
                "error": (
                    f"Packet {p['packet_id']} ServerHello negotiated {p['tls_version']!r}; "
                    "TLS 1.2 is outside the TLS 1.3 correlation slice."
                ),
                "packets": [],
                "steps": [],
                "completeness": {"complete_handshake": False},
            }

    # Modular sequence tracking per direction to ensure wrap-safe retransmission detection
    highest_end_seq: dict[str, int] = {}
    syn_pkt: dict[str, Any] | None = None
    syn_ack_pkt: dict[str, Any] | None = None
    est_ack_pkt: dict[str, Any] | None = None

    for p in matched:
        d = p["direction"]
        fset = p["flags_set"]
        is_syn = "SYN" in fset
        is_ack = "ACK" in fset
        is_fin = "FIN" in fset
        if d == "C->S" and is_syn and not is_ack and syn_pkt is None:
            syn_pkt = p
            if p["seq"] is not None:
                highest_end_seq[d] = seq_add(p["seq"], 1)
            continue
        if d == "S->C" and is_syn and is_ack and syn_ack_pkt is None:
            if syn_pkt is None or (
                p["ack"] is not None
                and syn_pkt["seq"] is not None
                and p["ack"] == seq_add(syn_pkt["seq"], 1)
            ):
                syn_ack_pkt = p
                if p["seq"] is not None:
                    highest_end_seq[d] = seq_add(p["seq"], 1)
                continue
        if (
            d == "C->S"
            and is_ack
            and not is_syn
            and syn_ack_pkt is not None
            and est_ack_pkt is None
        ):
            if (
                p["ack"] is not None
                and syn_ack_pkt["seq"] is not None
                and p["ack"] == seq_add(syn_ack_pkt["seq"], 1)
            ):
                est_ack_pkt = p

        # Check modular sequence advance for data segments
        if p["tcp_len"] > 0 and p["seq"] is not None:
            seg_end = seq_add(p["seq"], p["tcp_len"] + (1 if is_fin else 0))
            if d in highest_end_seq:
                if seq_le(seg_end, highest_end_seq[d]):
                    p["retransmission"] = True
                else:
                    highest_end_seq[d] = seg_end
            else:
                highest_end_seq[d] = seg_end

    origin_ns = syn_pkt["ts_ns"] if syn_pkt is not None else matched[0]["ts_ns"]
    prev_ns = matched[0]["ts_ns"]
    timestamp_regressions = 0
    truncated_packets = 0

    packet_table: list[dict[str, Any]] = []
    for idx, p in enumerate(matched):
        if idx > 0 and p["ts_ns"] < prev_ns:
            timestamp_regressions += 1
        delta_us = 0 if idx == 0 else int(round((p["ts_ns"] - prev_ns) / 1000.0))
        rel_us = int(round((p["ts_ns"] - origin_ns) / 1000.0))
        prev_ns = p["ts_ns"]
        if p["cap_len"] < p["frame_len"]:
            truncated_packets += 1

        tls_info = ""
        if p["tls_hs_type"] == "1":
            parts = ["ClientHello"]
            if p["tls_version"]:
                parts.append(p["tls_version"])
            if p["tls_sni"]:
                parts.append(f"sni={p['tls_sni']}")
            if p["tls_alpn"]:
                parts.append(f"alpn={p['tls_alpn']}")
            tls_info = " ".join(parts)
        elif p["tls_hs_type"] == "2":
            parts = ["ServerHello"]
            if p["tls_version"]:
                parts.append(p["tls_version"])
            if p["tls_alpn"]:
                parts.append(f"alpn={p['tls_alpn']}")
            if p["tls_cipher_suite"]:
                parts.append(f"cipher=0x{int(p['tls_cipher_suite']):04x}")
            tls_info = " ".join(parts)
        elif p["tcp_len"] > 0:
            tls_info = "Encrypted TLS 1.3 record / TCP segment payload"

        p["rel_us"] = rel_us
        p["delta_us"] = delta_us
        p["tls_info"] = tls_info

        packet_table.append({
            "dsl_index": p["dsl_index"],
            "packet_id": p["packet_id"],
            "direction": p["direction"],
            "rel_us": rel_us,
            "delta_us": delta_us,
            "seq": p["seq"] if p["seq"] is not None else "",
            "ack": p["ack"] if (p["ack"] is not None and "ACK" in p["flags_set"]) else "",
            "flags": p["flags"],
            "tcp_len": p["tcp_len"],
            "frame_len": p["frame_len"],
            "cap_len": p["cap_len"],
            "retransmission": p["retransmission"],
            "tls_info": tls_info,
        })

    # Build Steps Table (§3.1 & §3.2)
    timings = manifest.get("timings", {})
    steps: list[dict[str, Any]] = []
    order = 0

    def add_step(
        *,
        layer: str,
        direction: str,
        label: str,
        trace_len: int | None,
        packet_ids: list[int],
        candidate_packet_ids: list[int],
        seq_range: str,
        ack_range: str,
        app_start_us: int | None,
        app_end_us: int | None,
        pkt_rows: list[dict[str, Any]],
        evidence: str,
        explanation: str,
    ) -> None:
        nonlocal order
        order += 1
        pkt_first_us = pkt_rows[0]["rel_us"] if pkt_rows else None
        pkt_last_us = pkt_rows[-1]["rel_us"] if pkt_rows else None
        steps.append({
            "order": order,
            "layer": layer,
            "direction": direction,
            "label": label,
            "trace_len": trace_len,
            "packet_ids": packet_ids,
            "candidate_packet_ids": candidate_packet_ids,
            "seq_range": seq_range,
            "ack_range": ack_range,
            "app_start_us": app_start_us,
            "app_end_us": app_end_us,
            "pkt_first_us": pkt_first_us,
            "pkt_last_us": pkt_last_us,
            "evidence": evidence,
            "explanation": explanation,
        })

    t_conn_start = timings.get("connect_start_us", 0 if timings.get("tcp_connect_us") is not None else None)
    t_conn_end = (
        (t_conn_start + timings["tcp_connect_us"])
        if (t_conn_start is not None and timings.get("tcp_connect_us") is not None)
        else None
    )

    # 1. TCP SYN
    if syn_pkt is not None:
        add_step(
            layer="tcp",
            direction="C->S",
            label="TCP SYN",
            trace_len=0,
            packet_ids=[syn_pkt["packet_id"]],
            candidate_packet_ids=[syn_pkt["packet_id"]],
            seq_range=fmt_seq_range(syn_pkt["seq"], 1),
            ack_range="",
            app_start_us=t_conn_start,
            app_end_us=t_conn_end,
            pkt_rows=[syn_pkt],
            evidence="exact",
            explanation="Exact captured client TCP SYN initiating connection.",
        )
    else:
        add_step(
            layer="tcp",
            direction="C->S",
            label="TCP SYN",
            trace_len=0,
            packet_ids=[],
            candidate_packet_ids=[],
            seq_range="",
            ack_range="",
            app_start_us=t_conn_start,
            app_end_us=t_conn_end,
            pkt_rows=[],
            evidence="missing",
            explanation="Capture started after client TCP SYN (has_syn=false).",
        )

    # 2. TCP SYN-ACK
    if syn_ack_pkt is not None:
        add_step(
            layer="tcp",
            direction="S->C",
            label="TCP SYN-ACK",
            trace_len=0,
            packet_ids=[syn_ack_pkt["packet_id"]],
            candidate_packet_ids=[syn_ack_pkt["packet_id"]],
            seq_range=fmt_seq_range(syn_ack_pkt["seq"], 1),
            ack_range=str(syn_ack_pkt["ack"]) if syn_ack_pkt["ack"] is not None else "",
            app_start_us=t_conn_start,
            app_end_us=t_conn_end,
            pkt_rows=[syn_ack_pkt],
            evidence="exact",
            explanation="Exact captured server TCP SYN-ACK acknowledging client SYN modulo 2^32.",
        )
    else:
        add_step(
            layer="tcp",
            direction="S->C",
            label="TCP SYN-ACK",
            trace_len=0,
            packet_ids=[],
            candidate_packet_ids=[],
            seq_range="",
            ack_range="",
            app_start_us=t_conn_start,
            app_end_us=t_conn_end,
            pkt_rows=[],
            evidence="missing",
            explanation="Server TCP SYN-ACK was not observed in the capture window.",
        )

    # 3. TCP Establishing ACK
    if est_ack_pkt is not None:
        piggy = est_ack_pkt["tcp_len"] > 0
        expl = (
            f"Exact captured establishing ACK covering server SYN; also carries {est_ack_pkt['tcp_len']} bytes of initial TLS payload."
            if piggy
            else "Exact captured standalone 0-byte establishing ACK completing 3-way handshake."
        )
        add_step(
            layer="tcp",
            direction="C->S",
            label="TCP Establishing ACK",
            trace_len=0,
            packet_ids=[est_ack_pkt["packet_id"]],
            candidate_packet_ids=[est_ack_pkt["packet_id"]],
            seq_range=fmt_seq_range(est_ack_pkt["seq"], est_ack_pkt["tcp_len"]),
            ack_range=str(est_ack_pkt["ack"]) if est_ack_pkt["ack"] is not None else "",
            app_start_us=t_conn_start,
            app_end_us=t_conn_end,
            pkt_rows=[est_ack_pkt],
            evidence="exact",
            explanation=expl,
        )
    else:
        add_step(
            layer="tcp",
            direction="C->S",
            label="TCP Establishing ACK",
            trace_len=0,
            packet_ids=[],
            candidate_packet_ids=[],
            seq_range="",
            ack_range="",
            app_start_us=t_conn_start,
            app_end_us=t_conn_end,
            pkt_rows=[],
            evidence="missing",
            explanation="Client establishing ACK was not observed in the capture window.",
        )

    # Partition data packets into protocol flights based on direction and handshake landmarks
    data_pkts = [p for p in matched if p["tcp_len"] > 0]
    non_retrans_data = [p for p in data_pkts if not p["retransmission"]]

    # Locate ServerHello packet index in matched packets
    sh_pkt_candidates = [p for p in non_retrans_data if p["direction"] == "S->C" and p["tls_hs_type"] == "2"]
    first_sc_pkt = sh_pkt_candidates[0] if sh_pkt_candidates else next((p for p in non_retrans_data if p["direction"] == "S->C"), None)
    sh_pkt_id = first_sc_pkt["packet_id"] if first_sc_pkt else None

    # ClientHello flight: C->S data packets before first S->C packet (or with tls_hs_type=="1")
    ch_primary = [
        p for p in non_retrans_data
        if p["direction"] == "C->S" and (sh_pkt_id is None or p["packet_id"] < sh_pkt_id)
    ]
    ch_all_candidates = [
        p for p in data_pkts
        if p["direction"] == "C->S" and (sh_pkt_id is None or p["packet_id"] < sh_pkt_id)
    ]

    # Client post-ServerHello data packets (Client Finished + HTTP Request + optional close_notify)
    client_post_sh_primary = [
        p for p in non_retrans_data
        if p["direction"] == "C->S" and (sh_pkt_id is not None and p["packet_id"] > sh_pkt_id)
    ]
    client_post_sh_all = [
        p for p in data_pkts
        if p["direction"] == "C->S" and (sh_pkt_id is not None and p["packet_id"] > sh_pkt_id)
    ]
    first_client_post_sh_id = client_post_sh_primary[0]["packet_id"] if client_post_sh_primary else None

    # Server post-ServerHello packets before client's post-ServerHello flight vs after
    server_hs_flight_primary: list[dict[str, Any]] = []
    server_hs_flight_all: list[dict[str, Any]] = []
    server_app_flight_primary: list[dict[str, Any]] = []
    server_app_flight_all: list[dict[str, Any]] = []

    trace_events = parse_ssl_trace(trace_text, handshake_trace_text)
    has_server_post_hs_or_app = any(
        ev["direction"] == "S->C" and (ev["label"] == "NewSessionTicket" or ev["kind"] == "appdata")
        for ev in trace_events
    )

    # Check if ServerHello TCP segment is larger than the ServerHello TLS record (coalesced with encrypted handshake records)
    sh_trace_ev = next((ev for ev in trace_events if ev["label"] == "ServerHello"), None)
    sh_wire_record_len = (5 + sh_trace_ev["outer_record_len"]) if (sh_trace_ev and sh_trace_ev["outer_record_len"] is not None) else None
    sh_coalesced_segment = bool(
        first_sc_pkt is not None
        and sh_wire_record_len is not None
        and first_sc_pkt["tcp_len"] > sh_wire_record_len
    )

    for p in data_pkts:
        if p["direction"] != "S->C":
            continue
        if first_sc_pkt is not None and p["packet_id"] == first_sc_pkt["packet_id"] and not sh_coalesced_segment:
            continue
        if first_client_post_sh_id is not None and p["packet_id"] < first_client_post_sh_id:
            server_hs_flight_all.append(p)
            if not p["retransmission"]:
                server_hs_flight_primary.append(p)
        elif first_client_post_sh_id is not None and p["packet_id"] > first_client_post_sh_id:
            server_app_flight_all.append(p)
            if not p["retransmission"]:
                server_app_flight_primary.append(p)
        else:
            # No client post-SH packet separates server handshake flight from server app flight
            server_hs_flight_all.append(p)
            if not p["retransmission"]:
                server_hs_flight_primary.append(p)

    server_flight_ambiguous = bool(
        first_client_post_sh_id is None
        and has_server_post_hs_or_app
        and len(server_hs_flight_all) > 0
    )

    first_server_app_id = server_app_flight_primary[0]["packet_id"] if server_app_flight_primary else None
    if first_server_app_id is not None:
        client_req_flight_primary = [p for p in client_post_sh_primary if p["packet_id"] < first_server_app_id] or client_post_sh_primary
        client_req_flight_all = [p for p in client_post_sh_all if p["packet_id"] < first_server_app_id] or client_post_sh_all
        client_close_flight_primary = [p for p in client_post_sh_primary if p["packet_id"] > first_server_app_id] or client_post_sh_primary[-1:]
        client_close_flight_all = [p for p in client_post_sh_all if p["packet_id"] > first_server_app_id] or client_post_sh_all[-1:]
    else:
        client_req_flight_primary = client_post_sh_primary
        client_req_flight_all = client_post_sh_all
        client_close_flight_primary = client_post_sh_primary[-1:]
        client_close_flight_all = client_post_sh_all[-1:]

    t_tls_start = t_conn_end
    t_tls_end = (
        (t_tls_start + timings["tls_handshake_us"])
        if (t_tls_start is not None and timings.get("tls_handshake_us") is not None)
        else None
    )
    t_write_start = t_tls_end
    t_write_end = (
        (t_write_start + timings["request_write_us"])
        if (t_write_start is not None and timings.get("request_write_us") is not None)
        else None
    )
    t_ttfb_end = (
        (t_write_end + timings["ttfb_us"])
        if (t_write_end is not None and timings.get("ttfb_us") is not None)
        else None
    )
    t_transfer_end = (
        (t_ttfb_end + timings["transfer_us"])
        if (t_ttfb_end is not None and timings.get("transfer_us") is not None)
        else None
    )
    t_close_start = t_transfer_end
    t_close_end = (
        (t_close_start + timings["close_call_us"])
        if (t_close_start is not None and timings.get("close_call_us") is not None)
        else None
    )

    def pkt_seq_span(pkts: list[dict[str, Any]]) -> tuple[str, str]:
        if not pkts or pkts[0]["seq"] is None:
            return "", ""
        total_len = sum(x["tcp_len"] for x in pkts)
        s_rng = fmt_seq_range(pkts[0]["seq"], total_len)
        acks = [str(x["ack"]) for x in pkts if x["ack"] is not None]
        a_rng = acks[0] if len(set(acks)) == 1 else (f"{acks[0]}..{acks[-1]}" if acks else "")
        return s_rng, a_rng

    # Emit TLS / HTTP steps in trace order
    seen_http_request = False
    seen_http_response = False
    seen_close_notify = False

    for ev in trace_events:
        lbl = ev["label"]
        d = ev["direction"]
        tlen = ev["trace_len"]

        if lbl == "ChangeCipherSpec":
            # TLS 1.3 middlebox compatibility CCS record
            cand_pkts = ch_all_candidates if d == "C->S" and not client_req_flight_all else (
                client_req_flight_all if d == "C->S" else (server_hs_flight_all or ([first_sc_pkt] if first_sc_pkt else []))
            )
            s_rng, a_rng = pkt_seq_span([p for p in cand_pkts if not p["retransmission"]] or cand_pkts)
            add_step(
                layer="tls",
                direction=d,
                label="ChangeCipherSpec",
                trace_len=tlen,
                packet_ids=[],
                candidate_packet_ids=[p["packet_id"] for p in cand_pkts],
                seq_range=s_rng,
                ack_range=a_rng,
                app_start_us=t_tls_start,
                app_end_us=t_tls_end,
                pkt_rows=[p for p in cand_pkts if not p["retransmission"]] or cand_pkts,
                evidence="flight" if cand_pkts else "app_only",
                explanation="TLS 1.3 compatibility ChangeCipherSpec record observed in SSL_trace.",
            )
            continue

        if lbl == "ClientHello":
            vis_ch = [p for p in ch_primary if p["tls_hs_type"] == "1"]
            if (
                len(ch_primary) == 1
                and len(vis_ch) == 1
                and not ev["coalesced_in_record"]
                and not ev["split_across_records"]
            ):
                p0 = ch_primary[0]
                s_rng, a_rng = pkt_seq_span([p0])
                add_step(
                    layer="tls",
                    direction="C->S",
                    label="ClientHello",
                    trace_len=tlen,
                    packet_ids=[p0["packet_id"]],
                    candidate_packet_ids=[p["packet_id"] for p in ch_all_candidates],
                    seq_range=s_rng,
                    ack_range=a_rng,
                    app_start_us=t_tls_start,
                    app_end_us=t_tls_end,
                    pkt_rows=ch_primary,
                    evidence="exact",
                    explanation="Unambiguous single-packet visible TLS 1.3 ClientHello dissected by lmdebug pcap.",
                )
            elif ch_all_candidates:
                s_rng, a_rng = pkt_seq_span(ch_primary or ch_all_candidates)
                add_step(
                    layer="tls",
                    direction="C->S",
                    label="ClientHello",
                    trace_len=tlen,
                    packet_ids=[],
                    candidate_packet_ids=[p["packet_id"] for p in ch_all_candidates],
                    seq_range=s_rng,
                    ack_range=a_rng,
                    app_start_us=t_tls_start,
                    app_end_us=t_tls_end,
                    pkt_rows=ch_primary or ch_all_candidates,
                    evidence="flight",
                    explanation=(
                        f"ClientHello spans {len(ch_primary)} TCP segment(s) or coalesced records; "
                        "all contributing client flight packets recorded as candidates."
                    ),
                )
            else:
                add_step(
                    layer="tls",
                    direction="C->S",
                    label="ClientHello",
                    trace_len=tlen,
                    packet_ids=[],
                    candidate_packet_ids=[],
                    seq_range="",
                    ack_range="",
                    app_start_us=t_tls_start,
                    app_end_us=t_tls_end,
                    pkt_rows=[],
                    evidence="app_only",
                    explanation="ClientHello recorded in SSL_trace but no matching client packet captured.",
                )
            continue

        if lbl in ("ServerHello", "HelloRetryRequest"):
            if (
                first_sc_pkt is not None
                and first_sc_pkt["tls_hs_type"] == "2"
                and not sh_coalesced_segment
                and not ev["coalesced_in_record"]
                and not ev["split_across_records"]
            ):
                s_rng, a_rng = pkt_seq_span([first_sc_pkt])
                add_step(
                    layer="tls",
                    direction="S->C",
                    label=lbl,
                    trace_len=tlen,
                    packet_ids=[first_sc_pkt["packet_id"]],
                    candidate_packet_ids=[first_sc_pkt["packet_id"]],
                    seq_range=s_rng,
                    ack_range=a_rng,
                    app_start_us=t_tls_start,
                    app_end_us=t_tls_end,
                    pkt_rows=[first_sc_pkt],
                    evidence="exact",
                    explanation=f"Unambiguous visible TLS 1.3 {lbl} dissected by lmdebug pcap.",
                )
            elif first_sc_pkt is not None:
                cands = [first_sc_pkt] + [p for p in server_hs_flight_all if p["packet_id"] != first_sc_pkt["packet_id"]]
                s_rng, a_rng = pkt_seq_span([first_sc_pkt])
                add_step(
                    layer="tls",
                    direction="S->C",
                    label=lbl,
                    trace_len=tlen,
                    packet_ids=[],
                    candidate_packet_ids=[p["packet_id"] for p in cands],
                    seq_range=s_rng,
                    ack_range=a_rng,
                    app_start_us=t_tls_start,
                    app_end_us=t_tls_end,
                    pkt_rows=[first_sc_pkt],
                    evidence="flight",
                    explanation=(
                        f"{lbl} shares a TCP segment or record with subsequent handshake bytes; "
                        "reported at flight granularity without claiming standalone packet boundaries."
                    ),
                )
            else:
                add_step(
                    layer="tls",
                    direction="S->C",
                    label=lbl,
                    trace_len=tlen,
                    packet_ids=[],
                    candidate_packet_ids=[],
                    seq_range="",
                    ack_range="",
                    app_start_us=t_tls_start,
                    app_end_us=t_tls_end,
                    pkt_rows=[],
                    evidence="app_only",
                    explanation=f"{lbl} present in SSL_trace but missing from captured server packets.",
                )
            continue

        if d == "S->C" and lbl in ("EncryptedExtensions", "CertificateRequest", "Certificate", "CertificateVerify", "Finished"):
            step_lbl = "Server Finished" if lbl == "Finished" else lbl
            if server_flight_ambiguous:
                s_rng, a_rng = pkt_seq_span(server_hs_flight_primary or server_hs_flight_all)
                add_step(
                    layer="tls",
                    direction="S->C",
                    label=step_lbl,
                    trace_len=tlen,
                    packet_ids=[],
                    candidate_packet_ids=[p["packet_id"] for p in server_hs_flight_all],
                    seq_range=s_rng,
                    ack_range=a_rng,
                    app_start_us=t_tls_start,
                    app_end_us=t_tls_end,
                    pkt_rows=server_hs_flight_primary or server_hs_flight_all,
                    evidence="ambiguous",
                    explanation=(
                        f"SSL_trace confirms encrypted {step_lbl} (plaintext length {tlen} B), "
                        "but server handshake and post-handshake/application records share an unseparated "
                        "encrypted packet sequence without TLS key-log decryption."
                    ),
                )
            elif server_hs_flight_all:
                s_rng, a_rng = pkt_seq_span(server_hs_flight_primary or server_hs_flight_all)
                retrans_ids = [p["packet_id"] for p in server_hs_flight_all if p["retransmission"]]
                retrans_note = (
                    f" Retransmitted packet(s) {retrans_ids} retained in packet table and candidate set."
                    if retrans_ids
                    else ""
                )
                add_step(
                    layer="tls",
                    direction="S->C",
                    label=step_lbl,
                    trace_len=tlen,
                    packet_ids=[],
                    candidate_packet_ids=[p["packet_id"] for p in server_hs_flight_all],
                    seq_range=s_rng,
                    ack_range=a_rng,
                    app_start_us=t_tls_start,
                    app_end_us=t_tls_end,
                    pkt_rows=server_hs_flight_primary or server_hs_flight_all,
                    evidence="flight",
                    explanation=(
                        f"SSL_trace confirms {step_lbl} (plaintext handshake body {tlen} B); "
                        "TLS 1.3 encrypts post-ServerHello handshake messages inside outer ApplicationData(23) "
                        f"records, so attribution is server handshake flight-only.{retrans_note}"
                    ),
                )
            else:
                add_step(
                    layer="tls",
                    direction="S->C",
                    label=step_lbl,
                    trace_len=tlen,
                    packet_ids=[],
                    candidate_packet_ids=[],
                    seq_range="",
                    ack_range="",
                    app_start_us=t_tls_start,
                    app_end_us=t_tls_end,
                    pkt_rows=[],
                    evidence="app_only",
                    explanation=f"SSL_trace confirms {step_lbl}, but no server encrypted handshake packets were captured.",
                )
            continue

        if d == "C->S" and lbl == "Finished":
            # Client Finished can either be the first C->S encrypted packet or share the flight with HTTP request
            cands = client_req_flight_all
            prim = client_req_flight_primary or cands
            s_rng, a_rng = pkt_seq_span(prim)
            add_step(
                layer="tls",
                direction="C->S",
                label="Client Finished",
                trace_len=tlen,
                packet_ids=[],
                candidate_packet_ids=[p["packet_id"] for p in cands],
                seq_range=s_rng,
                ack_range=a_rng,
                app_start_us=t_tls_start,
                app_end_us=t_tls_end,
                pkt_rows=prim,
                evidence="flight" if cands else "app_only",
                explanation=(
                    "SSL_trace confirms Client Finished (plaintext body "
                    f"{tlen} B); encrypted client flight after ServerHello flight may share transport segments "
                    "with application request records."
                ),
            )
            continue

        if d == "C->S" and ev["kind"] == "appdata":
            if seen_http_request:
                continue
            seen_http_request = True
            req_bytes = manifest.get("http", {}).get("request_bytes", tlen)
            cands = client_req_flight_all
            prim = client_req_flight_primary or cands
            s_rng, a_rng = pkt_seq_span(prim)
            add_step(
                layer="http",
                direction="C->S",
                label="HTTP Request",
                trace_len=req_bytes,
                packet_ids=[],
                candidate_packet_ids=[p["packet_id"] for p in cands],
                seq_range=s_rng,
                ack_range=a_rng,
                app_start_us=t_write_start,
                app_end_us=t_write_end,
                pkt_rows=prim,
                evidence="flight" if cands else "app_only",
                explanation=(
                    f"Application Tls.write confirmed {req_bytes} plaintext HTTP/1.1 request bytes; "
                    "wire packets carry encrypted TLS 1.3 ApplicationData records in the client flight."
                ),
            )
            continue

        if d == "S->C" and lbl == "NewSessionTicket":
            cands = server_app_flight_all if not server_flight_ambiguous else server_hs_flight_all
            prim = (server_app_flight_primary if not server_flight_ambiguous else server_hs_flight_primary) or cands
            s_rng, a_rng = pkt_seq_span(prim)
            ev_kind = "ambiguous" if server_flight_ambiguous else ("flight" if cands else "app_only")
            add_step(
                layer="tls",
                direction="S->C",
                label="NewSessionTicket",
                trace_len=tlen,
                packet_ids=[],
                candidate_packet_ids=[p["packet_id"] for p in cands],
                seq_range=s_rng,
                ack_range=a_rng,
                app_start_us=t_write_end,
                app_end_us=t_transfer_end,
                pkt_rows=prim,
                evidence=ev_kind,
                explanation=(
                    f"Post-handshake TLS 1.3 NewSessionTicket (plaintext body {tlen} B) observed in SSL_trace; "
                    "shares encrypted server flight with post-handshake/response records."
                ),
            )
            continue

        if d == "S->C" and ev["kind"] == "appdata":
            if seen_http_response:
                continue
            seen_http_response = True
            resp_bytes = manifest.get("http", {}).get("response_bytes", tlen)
            cands = server_app_flight_all if not server_flight_ambiguous else server_hs_flight_all
            prim = (server_app_flight_primary if not server_flight_ambiguous else server_hs_flight_primary) or cands
            s_rng, a_rng = pkt_seq_span(prim)
            ev_kind = "ambiguous" if server_flight_ambiguous else ("flight" if cands else "app_only")
            add_step(
                layer="http",
                direction="S->C",
                label="HTTP Response",
                trace_len=resp_bytes,
                packet_ids=[],
                candidate_packet_ids=[p["packet_id"] for p in cands],
                seq_range=s_rng,
                ack_range=a_rng,
                app_start_us=t_write_end,
                app_end_us=t_transfer_end,
                pkt_rows=prim,
                evidence=ev_kind,
                explanation=(
                    f"Application Tls.read confirmed {resp_bytes} plaintext HTTP/1.1 response bytes "
                    "(first byte TTFB measured via 1-byte read); wire packets are encrypted TLS 1.3 records."
                ),
            )
            continue

        if ev["kind"] == "alert":
            if lbl == "TLS close_notify":
                seen_close_notify = True
            cands = client_close_flight_all if d == "C->S" else (server_app_flight_all or server_hs_flight_all)
            prim = (client_close_flight_primary if d == "C->S" else (server_app_flight_primary or server_hs_flight_primary)) or cands
            s_rng, a_rng = pkt_seq_span(prim)
            add_step(
                layer="tls",
                direction=d,
                label=lbl,
                trace_len=tlen,
                packet_ids=[],
                candidate_packet_ids=[p["packet_id"] for p in cands],
                seq_range=s_rng,
                ack_range=a_rng,
                app_start_us=t_close_start if d == "C->S" else None,
                app_end_us=t_close_end if d == "C->S" else None,
                pkt_rows=prim,
                evidence="flight" if prim else "app_only",
                explanation=(
                    f"{lbl} alert recorded in SSL_trace; Tls.shutdown() sends one SSL_shutdown call "
                    "(close_call_kind=tls_shutdown_attempt) and is distinct from TCP FIN/RST socket closure."
                ),
            )
            continue

        # Any other unknown or optional trace record (e.g. KeyUpdate, UnknownTraceRecord)
        add_step(
            layer="tls",
            direction=d,
            label=lbl,
            trace_len=tlen,
            packet_ids=[],
            candidate_packet_ids=[],
            seq_range="",
            ack_range="",
            app_start_us=None,
            app_end_us=None,
            pkt_rows=[],
            evidence="app_only",
            explanation=f"Trace record {lbl} preserved from SSL_trace without fabricated packet mapping.",
        )

    if not seen_close_notify and timings.get("close_call_us") is not None:
        add_step(
            layer="tls",
            direction="C->S",
            label="TLS close_notify",
            trace_len=None,
            packet_ids=[],
            candidate_packet_ids=[],
            seq_range="",
            ack_range="",
            app_start_us=t_close_start,
            app_end_us=t_close_end,
            pkt_rows=[],
            evidence="app_only",
            explanation=(
                "Tls.shutdown() call timed in application (close_call_kind=tls_shutdown_attempt); "
                "no separate unencrypted close_notify packet claim."
            ),
        )

    # Final step: TCP Teardown (FIN/ACK or RST)
    first_teardown_idx = next(
        (i for i, p in enumerate(matched) if ("FIN" in p["flags_set"] or "RST" in p["flags_set"])),
        None,
    )
    teardown_pkts = matched[first_teardown_idx:] if first_teardown_idx is not None else []
    has_fin_or_rst = len(teardown_pkts) > 0
    if has_fin_or_rst:
        has_rst = any("RST" in p["flags_set"] for p in teardown_pkts)
        disconnect_status = "rst_teardown" if has_rst else "fin_teardown"
        disconnect_us = teardown_pkts[-1]["rel_us"] - teardown_pkts[0]["rel_us"]
        s_rng, a_rng = pkt_seq_span(teardown_pkts[:1])
        add_step(
            layer="tcp",
            direction="both",
            label="TCP Teardown (FIN/RST)",
            trace_len=0,
            packet_ids=[p["packet_id"] for p in teardown_pkts],
            candidate_packet_ids=[p["packet_id"] for p in teardown_pkts],
            seq_range=s_rng,
            ack_range=a_rng,
            app_start_us=None,
            app_end_us=None,
            pkt_rows=teardown_pkts,
            evidence="exact",
            explanation=(
                f"Captured TCP {'RST' if has_rst else 'FIN/ACK'} teardown sequence across "
                f"{len(teardown_pkts)} packet(s) ({disconnect_us} us on capture axis)."
            ),
        )
    else:
        disconnect_status = "missing_fin_or_rst"
        disconnect_us = None
        add_step(
            layer="tcp",
            direction="both",
            label="TCP Teardown (FIN/RST)",
            trace_len=0,
            packet_ids=[],
            candidate_packet_ids=[],
            seq_range="",
            ack_range="",
            app_start_us=None,
            app_end_us=None,
            pkt_rows=[],
            evidence="missing",
            explanation="No TCP FIN or RST packets were observed for this tuple before capture ended.",
        )

    completeness = {
        "has_syn": syn_pkt is not None,
        "has_syn_ack": syn_ack_pkt is not None,
        "has_est_ack": est_ack_pkt is not None,
        "has_fin_teardown": has_fin_or_rst,
        "truncated_packets": truncated_packets,
        "timestamp_regressions": timestamp_regressions,
        "ignored_tuple_packets": ignored_count,
        "matched_packets": len(matched),
        "early_capture_limit": len(dissected_rows) >= int(manifest.get("capture", {}).get("packet_limit", 100000)),
        "complete_handshake": bool(
            syn_pkt is not None
            and syn_ack_pkt is not None
            and est_ack_pkt is not None
            and first_sc_pkt is not None
        ),
    }

    timings_out = dict(timings)
    timings_out["close_call_kind"] = timings.get("close_call_kind", "tls_shutdown_attempt")
    timings_out["disconnect_us"] = disconnect_us
    timings_out["disconnect_status"] = disconnect_status

    return {
        "ok": True,
        "status": "ok",
        "packets": packet_table,
        "steps": steps,
        "completeness": completeness,
        "timings": timings_out,
    }


def write_correlation_artifacts(
    out_dir: pathlib.Path,
    manifest: dict[str, Any],
    trace_text: str,
    corr: dict[str, Any],
) -> None:
    """Write packets.csv, steps.json, steps.csv, request.json, tls-trace.txt, and report.md."""
    out_dir.mkdir(parents=True, exist_ok=True)

    full_manifest = dict(manifest)
    full_manifest["format_version"] = FORMAT_VERSION
    full_manifest["trace_parser_version"] = TRACE_PARSER_VERSION
    full_manifest["status"] = corr["status"]
    full_manifest["completeness"] = corr.get("completeness", {})
    if "timings" in corr:
        full_manifest["timings"] = corr["timings"]

    (out_dir / "request.json").write_text(
        json.dumps(full_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "tls-trace.txt").write_text(trace_text, encoding="utf-8")

    # packets.csv
    pkt_cols = [
        "packet_id",
        "direction",
        "rel_us",
        "delta_us",
        "seq",
        "ack",
        "flags",
        "tcp_len",
        "frame_len",
        "cap_len",
        "retransmission",
        "tls_info",
    ]
    with (out_dir / "packets.csv").open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp, lineterminator="\n")
        writer.writerow(pkt_cols)
        for p in corr["packets"]:
            writer.writerow([
                p["packet_id"],
                p["direction"],
                p["rel_us"],
                p["delta_us"],
                p["seq"],
                p["ack"],
                p["flags"],
                p["tcp_len"],
                p["frame_len"],
                p["cap_len"],
                "true" if p["retransmission"] else "false",
                p["tls_info"],
            ])

    # steps.json
    steps_doc = {
        "format_version": FORMAT_VERSION,
        "trace_parser_version": TRACE_PARSER_VERSION,
        "mode": full_manifest.get("mode", "replay_fixture"),
        "status": corr["status"],
        "time_axes_note": (
            "app_*_us values use lmssl process-local steady_clock (ssl.monotonic_us()); "
            "pkt_*_us values use libpcap/pcapng capture timestamps relative to the first captured SYN. "
            "The two clocks have distinct origins and are NEVER subtracted."
        ),
        "steps": corr["steps"],
    }
    (out_dir / "steps.json").write_text(
        json.dumps(steps_doc, indent=2) + "\n", encoding="utf-8"
    )

    # steps.csv
    step_cols = [
        "order",
        "layer",
        "direction",
        "label",
        "trace_len",
        "packet_ids",
        "candidate_packet_ids",
        "seq_range",
        "ack_range",
        "app_start_us",
        "app_end_us",
        "pkt_first_us",
        "pkt_last_us",
        "evidence",
        "explanation",
    ]
    with (out_dir / "steps.csv").open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp, lineterminator="\n")
        writer.writerow(step_cols)
        for s in corr["steps"]:
            writer.writerow([
                s["order"],
                s["layer"],
                s["direction"],
                s["label"],
                "" if s["trace_len"] is None else s["trace_len"],
                ";".join(str(x) for x in s["packet_ids"]),
                ";".join(str(x) for x in s["candidate_packet_ids"]),
                s["seq_range"],
                s["ack_range"],
                "" if s["app_start_us"] is None else s["app_start_us"],
                "" if s["app_end_us"] is None else s["app_end_us"],
                "" if s["pkt_first_us"] is None else s["pkt_first_us"],
                "" if s["pkt_last_us"] is None else s["pkt_last_us"],
                s["evidence"],
                s["explanation"],
            ])

    # report.md
    tup = full_manifest["tuple"]
    tls_info = full_manifest.get("tls", {})
    tim = full_manifest.get("timings", {})
    comp = full_manifest.get("completeness", {})
    lines = [
        "# HTTPS Packet & TLS 1.3 Flight Correlation Report",
        "",
        f"- **Mode:** `{full_manifest.get('mode', 'replay_fixture')}` "
        f"(synthetic_capture=`{full_manifest.get('synthetic_capture', False)}`, "
        f"synthetic_timings=`{full_manifest.get('synthetic_timings', False)}`)",
        f"- **Target URL:** `{full_manifest.get('url', '')}`",
        f"- **Selected Tuple:** `{tup['client_ip']}:{tup['client_port']} -> {tup['server_ip']}:{tup['server_port']}` (`{tup.get('family', 'ipv4')}`)",
        f"- **Capture Interface / Filter:** `{full_manifest.get('capture', {}).get('interface', 'offline')}` / `{full_manifest.get('capture', {}).get('bpf_filter', 'offline')}`",
        f"- **Negotiated TLS:** `{tls_info.get('version', '')}` / `{tls_info.get('cipher', '')}` / group `{tls_info.get('group', '')}` / ALPN `{tls_info.get('alpn', '')}` / verify `{tls_info.get('verify_result', '')}`",
        f"- **Time Axes:** Application `ssl.monotonic_us()` steady-clock axis (`app_*_us`, origin = measured request start) and capture `pkt_time` axis (`pkt_*_us`, origin = first captured SYN) have independent origins and are **never subtracted**.",
        f"- **Completeness:** `has_syn={comp.get('has_syn')}`, `has_syn_ack={comp.get('has_syn_ack')}`, `has_est_ack={comp.get('has_est_ack')}`, `has_fin_teardown={comp.get('has_fin_teardown')}`, `matched_packets={comp.get('matched_packets')}`, `ignored_tuple_packets={comp.get('ignored_tuple_packets')}`",
        "",
        "## Application Segment Timings (`ssl.monotonic_us()`) & Capture Teardown",
        "",
        "| Segment | Microseconds (`us`) | Milliseconds (`ms`) | Notes |",
        "| --- | ---: | ---: | --- |",
        f"| DNS preflight (`net.resolve`) | {tim.get('dns_us', 'null')} | {fmt_ms(tim.get('dns_us'))} | Untimed preflight lookup before capture/connect |",
        f"| TCP connect (`net.connect`) | {tim.get('tcp_connect_us', 'null')} | {fmt_ms(tim.get('tcp_connect_us'))} | Numeric IP connect call |",
        f"| TLS 1.3 handshake (`ctx.connect`) | {tim.get('tls_handshake_us', 'null')} | {fmt_ms(tim.get('tls_handshake_us'))} | Preserves original hostname SNI & verification |",
        f"| HTTP request write (`tls.write`) | {tim.get('request_write_us', 'null')} | {fmt_ms(tim.get('request_write_us'))} | Application write call completion |",
        f"| TTFB (`tls.read(1)`) | {tim.get('ttfb_us', 'null')} | {fmt_ms(tim.get('ttfb_us'))} | First response byte read minus request write end |",
        f"| Response transfer | {tim.get('transfer_us', 'null')} | {fmt_ms(tim.get('transfer_us'))} | Last positive read minus first response byte |",
        f"| EOF observation | {tim.get('eof_us', 'null')} | {fmt_ms(tim.get('eof_us'))} | EOF return minus last positive read |",
        f"| Close call (`{tim.get('close_call_kind', 'tls_shutdown_attempt')}`) | {tim.get('close_call_us', 'null')} | {fmt_ms(tim.get('close_call_us'))} | One `SSL_shutdown` call; does not close TCP socket |",
        f"| Captured TCP disconnect (`{tim.get('disconnect_status', '')}`) | {tim.get('disconnect_us', 'null')} | {fmt_ms(tim.get('disconnect_us'))} | Measured on capture axis from first FIN/RST to final teardown packet |",
        f"| Total / Accounted / Residual | {tim.get('total_us', 'null')} / {tim.get('accounted_us', 'null')} / {tim.get('residual_us', 'null')} | {fmt_ms(tim.get('total_us'))} | Scheduler/bookkeeping gap kept explicit in `residual_us` |",
        "",
        "## Step-to-Flight-to-Packet Correlation (`steps.csv`)",
        "",
        "| Order | Layer | Dir | Label | Trace Len | Exact Pkts | Candidate Pkts | Seq Range | Evidence | Explanation |",
        "| ---: | --- | --- | --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for s in corr["steps"]:
        tlen_s = "" if s["trace_len"] is None else str(s["trace_len"])
        p_ids = ";".join(str(x) for x in s["packet_ids"]) or "-"
        c_ids = ";".join(str(x) for x in s["candidate_packet_ids"]) or "-"
        lines.append(
            f"| {s['order']} | {s['layer']} | {s['direction']} | {s['label']} | {tlen_s} | {p_ids} | {c_ids} | `{s['seq_range'] or '-'}` | `{s['evidence']}` | {s['explanation']} |"
        )

    lines.extend([
        "",
        "## Captured Packet Table (`packets.csv`)",
        "",
        "| Pkt ID | Dir | Rel (`us`) | Delta (`us`) | Seq | Ack | Flags | TCP Len | Frame Len | Retrans | TLS / Dissector Info |",
        "| ---: | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | --- |",
    ])
    for p in corr["packets"]:
        lines.append(
            f"| {p['packet_id']} | {p['direction']} | {p['rel_us']} | {p['delta_us']} | {p['seq']} | {p['ack']} | `{p['flags']}` | {p['tcp_len']} | {p['frame_len']} | `{str(p['retransmission']).lower()}` | {p['tls_info'] or '-'} |"
        )
    lines.append("")
    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def build_deterministic_fixture(
    fixture_dir: pathlib.Path,
    lmdebug_bin: pathlib.Path,
    lmssl_bin: pathlib.Path,
    compiler_bin: pathlib.Path,
) -> None:
    """Generate deterministic offline replay fixtures under examples/correlation/fixtures/."""
    fixture_dir.mkdir(parents=True, exist_ok=True)
    cert_path = fixture_dir / "server-cert.pem"

    env = dict(os.environ)
    env["PATH"] = f"{lmssl_bin.parent}:{lmdebug_bin.parent}:{env.get('PATH', '')}"

    # 1. If server-cert.pem does not exist yet, generate a deterministic-metadata EC P-256 cert via lmssl
    if not cert_path.is_file():
        with tempfile.TemporaryDirectory(prefix="lmdebug-corr-cert-") as td:
            td_p = pathlib.Path(td)
            lms = td_p / "gen_cert.lms"
            dslb = td_p / "gen_cert.dslb"
            lms.write_text(
                f'''p = _lmcode_ cli="lmssl";
let ca_k = ssl.gen_ec("P-256");
let ca_c = ssl.new_cert(ca_k, "/CN=lmdebug Correlation Root CA")
    .serial(100)
    .ca(true)
    .valid_between("20260101000000Z", "20360101000000Z")
    .sign_self(ca_k, "SHA256");
let srv_k = ssl.gen_ec("P-256");
let srv_c = ssl.new_cert(srv_k, "/CN=edge.lmctl.ai")
    .serial(1001)
    .san("DNS:edge.lmctl.ai,IP:198.51.100.42")
    .valid_between("20260101000000Z", "20360101000000Z")
    .sign_with(ca_c, ca_k, "SHA256");
srv_c.save("{cert_path.as_posix()}");
end _lmcode_
savedsl(p, "{dslb.as_posix()}");
''',
                encoding="utf-8",
            )
            subprocess.run([str(compiler_bin), str(lms)], env=env, check=True, stdout=subprocess.DEVNULL)
            subprocess.run([str(lmssl_bin), "--lmcode", str(dslb)], env=env, check=True, stdout=subprocess.DEVNULL)

    cert_pem = cert_path.read_text(encoding="utf-8").strip()

    # 2. Build deterministic https_tls13.pcapng via lmdebug pcap
    pcapng_path = fixture_dir / "https_tls13.pcapng"
    with tempfile.TemporaryDirectory(prefix="lmdebug-corr-pcap-") as td:
        td_p = pathlib.Path(td)
        lms = td_p / "gen_pcap.lms"
        dslb = td_p / "gen_pcap.dslb"
        lms.write_text(
            f'''p = _lmcode_ cli="lmdebug pcap";
let cap = shark.capture();
let client_ip = "10.20.0.10";
let server_ip = "198.51.100.42";
let client_port = 54321;
let server_port = 443;

# 1..3: 3-way TCP handshake (SYN=1000, SYN-ACK=5000/1001, Establishing ACK=1001/5001)
cap.tcp_handshake(0.000000, client_ip, client_port, server_ip, server_port, 0.012000);

# 4: Unrelated background connection packet to verify strict 4-tuple filtering
cap.tcp_segment(0.012500, client_ip, 54322, server_ip, server_port, 9000, 0, "SYN", 64240, "");

# 5: ClientHello (TLS 1.3, SNI=edge.lmctl.ai, ALPN=http/1.1) -> 98-byte TLS record (seq 1001..1099)
cap.tls_client_hello(0.013000, client_ip, client_port, server_ip, server_port, 1001, 5001, "edge.lmctl.ai", "1.3", "http/1.1");

# 6: ServerHello (TLS 1.3, ALPN=http/1.1, cipher=0x1301 TLS_AES_128_GCM_SHA256) -> 70-byte TLS record (seq 5001..5071)
cap.tls_server_hello(0.025000, server_ip, server_port, client_ip, client_port, 5001, 1099, "1.3", "http/1.1", 4865);

# 7: Server encrypted handshake flight (EncryptedExtensions + Certificate + CertificateVerify + Server Finished) -> 645 B (seq 5071..5716)
cap.tls_app_data(0.025600, server_ip, server_port, client_ip, client_port, 5071, 1099, 640);

# 8: Retransmission of server encrypted handshake flight (same seq 5071, len 645 -> retransmission=true, not an extra step)
cap.tls_app_data(0.028600, server_ip, server_port, client_ip, client_port, 5071, 1099, 640);

# 9..10: Client encrypted Finished (79 B, seq 1099..1178) + HTTP/1.1 GET request flight (117 B, seq 1178..1295)
cap.tls_app_data(0.029200, client_ip, client_port, server_ip, server_port, 1099, 5716, 74);
cap.tls_app_data(0.029700, client_ip, client_port, server_ip, server_port, 1178, 5716, 112);

# 11: Server encrypted NewSessionTicket + HTTP/1.1 200 OK response flight (385 B, seq 5716..6101)
cap.tls_app_data(0.041500, server_ip, server_port, client_ip, client_port, 5716, 1295, 380);

# 12: Client encrypted close_notify alert (29 B, seq 1295..1324)
cap.tls_app_data(0.042200, client_ip, client_port, server_ip, server_port, 1295, 6101, 24);

# 13..16: 4-way TCP FIN teardown (client_seq=1324, server_seq=6101)
cap.tcp_close(0.043000, client_ip, client_port, server_ip, server_port, 1324, 6101, 0.012000);

cap.save_pcapng("{pcapng_path.as_posix()}");
end _lmcode_
savedsl(p, "{dslb.as_posix()}");
''',
            encoding="utf-8",
        )
        subprocess.run([str(compiler_bin), str(lms)], env=env, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([str(lmdebug_bin), "pcap", "--lmcode", str(dslb)], env=env, check=True, stdout=subprocess.DEVNULL)

    # 3. Deterministic OpenSSL 4.0.3 SSL_trace fixture matching the exchange
    trace_text = f"""Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 91
    ClientHello, Length=87
      client_version=0x303 (TLS 1.2)
      cipher_suites (len=2)
        {{0x13, 0x01}} TLS_AES_128_GCM_SHA256
      extensions, length = 44
        extension_type=server_name(0), length=18
          edge.lmctl.ai
        extension_type=application_layer_protocol_negotiation(16), length=11
          http/1.1
        extension_type=supported_versions(43), length=3
          TLS 1.3 (772)

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 65
    ServerHello, Length=61
      server_version=0x303 (TLS 1.2)
      cipher_suite {{0x13, 0x01}} TLS_AES_128_GCM_SHA256
      extensions, length = 21
        extension_type=supported_versions(43), length=2
          TLS 1.3 (772)
        extension_type=application_layer_protocol_negotiation(16), length=11
          http/1.1

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
    change_cipher_spec (1)

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 38
  Inner Content Type = Handshake (22)
    EncryptedExtensions, Length=17
      extensions, length = 15
        extension_type=application_layer_protocol_negotiation(16), length=11
          http/1.1

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 421
  Inner Content Type = Handshake (22)
    Certificate, Length=400
      context (len=0):
      certificate_list, length=396
{cert_pem}

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 97
  Inner Content Type = Handshake (22)
    CertificateVerify, Length=76
      Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 53
  Inner Content Type = Handshake (22)
    Finished, Length=32

Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
    change_cipher_spec (1)

Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 53
  Inner Content Type = Handshake (22)
    Finished, Length=32

Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 95
  Inner Content Type = ApplicationData (23)

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 180
  Inner Content Type = Handshake (22)
    NewSessionTicket, Length=159

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 190
  Inner Content Type = ApplicationData (23)

Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 19
  Inner Content Type = Alert (21)
    Level=warning(1), description=close notify(0)
"""
    (fixture_dir / "tls-trace.txt").write_text(trace_text, encoding="utf-8")

    # 4. Deterministic manifest fixture (request.json)
    manifest = {
        "format_version": FORMAT_VERSION,
        "mode": "replay_fixture",
        "synthetic_capture": True,
        "synthetic_timings": True,
        "attempt_id": "fixture-tls13-edge-001",
        "url": "https://edge.lmctl.ai/healthz",
        "selected_ip": "198.51.100.42",
        "tuple": {
            "client_ip": "10.20.0.10",
            "client_port": 54321,
            "server_ip": "198.51.100.42",
            "server_port": 443,
            "family": "ipv4",
        },
        "capture": {
            "interface": "offline-fixture",
            "bpf_filter": "host 198.51.100.42 and tcp port 443",
            "snaplen": 65535,
            "packet_limit": 100000,
            "duration_sec": 25.0,
            "startup_margin_sec": 0.0,
            "startup_margin_note": "Offline deterministic replay fixture; no live capture race.",
        },
        "tls": {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "group": "X25519",
            "alpn": "http/1.1",
            "server_name": "edge.lmctl.ai",
            "verified": True,
            "verify_result": "ok",
        },
        "http": {
            "method": "GET",
            "path": "/healthz",
            "status_code": 200,
            "request_bytes": 78,
            "response_bytes": 173,
        },
        "timings": {
            "dns_us": 1150,
            "connect_start_us": 0,
            "tcp_connect_us": 12400,
            "tls_handshake_us": 16800,
            "request_write_us": 500,
            "ttfb_us": 11800,
            "transfer_us": 350,
            "eof_us": 150,
            "close_call_us": 220,
            "close_call_kind": "tls_shutdown_attempt",
            "total_us": 42820,
            "accounted_us": 42220,
            "residual_us": 600,
        },
    }
    (fixture_dir / "request.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def run_offline_correlation(
    *,
    dissected_csv: pathlib.Path,
    fixture_dir: pathlib.Path,
    lmssl_verify_json: pathlib.Path,
    out_dir: pathlib.Path,
    lmdebug_bin: pathlib.Path | None = None,
    lmssl_bin: pathlib.Path | None = None,
) -> int:
    """Run offline replay correlation and emit all artifacts to out_dir."""
    manifest = json.loads((fixture_dir / "request.json").read_text(encoding="utf-8"))
    trace_text = (fixture_dir / "tls-trace.txt").read_text(encoding="utf-8")
    lmssl_info = json.loads(lmssl_verify_json.read_text(encoding="utf-8"))

    # Verify trace SHA-256 matches what lmssl computed in its DSL block
    expected_sha = sha256_bytes(trace_text.encode("utf-8"))
    if lmssl_info.get("trace_sha256", "").lower() != expected_sha.lower():
        raise AssertionError(
            f"lmssl trace SHA-256 mismatch: {lmssl_info.get('trace_sha256')} != {expected_sha}"
        )

    manifest["tools"] = {
        "lmssl_version": lmssl_info.get("lmssl_version", ""),
        "cert_subject": lmssl_info.get("cert_subject", ""),
        "cert_issuer": lmssl_info.get("cert_issuer", ""),
        "cert_fingerprint_sha256": lmssl_info.get("cert_fingerprint_sha256", ""),
        "trace_sha256": expected_sha,
        "monotonic_probe_delta_us": lmssl_info.get("monotonic_delta_us", 0),
    }
    if lmdebug_bin and lmdebug_bin.is_file():
        v = subprocess.check_output([str(lmdebug_bin), "pcap", "--version"], text=True).strip()
        s = subprocess.check_output([str(lmdebug_bin), "pcap", "--lmcode-schema", "--json"])
        manifest["tools"]["lmdebug_pcap_version"] = v
        manifest["tools"]["lmdebug_pcap_schema_sha256"] = sha256_bytes(s)
    if lmssl_bin and lmssl_bin.is_file():
        s = subprocess.check_output([str(lmssl_bin), "--lmcode-schema", "--json"])
        manifest["tools"]["lmssl_schema_sha256"] = sha256_bytes(s)

    rows = load_dissected_fields_csv(dissected_csv)
    corr = correlate_exchange(rows, trace_text, manifest)
    if not corr["ok"]:
        write_correlation_artifacts(out_dir, manifest, trace_text, corr)
        print(f"ERROR: {corr['error']}", file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    # Copy capture.pcapng into out_dir to satisfy the 7-file artifact contract
    src_pcap = fixture_dir / "https_tls13.pcapng"
    if src_pcap.is_file():
        (out_dir / "capture.pcapng").write_bytes(src_pcap.read_bytes())

    write_correlation_artifacts(out_dir, manifest, trace_text, corr)

    comp = corr["completeness"]
    print(f"mode={manifest['mode']} status={corr['status']} tuple={manifest['tuple']['client_ip']}:{manifest['tuple']['client_port']}->{manifest['tuple']['server_ip']}:{manifest['tuple']['server_port']}")
    print(f"packets={len(corr['packets'])} ignored_other_tuple={comp['ignored_tuple_packets']} steps={len(corr['steps'])}")
    print(f"completeness: syn={str(comp['has_syn']).lower()} syn_ack={str(comp['has_syn_ack']).lower()} est_ack={str(comp['has_est_ack']).lower()} fin={str(comp['has_fin_teardown']).lower()}")
    exact_labels = [s["label"] for s in corr["steps"] if s["evidence"] == "exact"]
    flight_labels = [s["label"] for s in corr["steps"] if s["evidence"] == "flight"]
    print("exact_steps=" + ",".join(exact_labels))
    print("flight_steps=" + ",".join(flight_labels))
    return 0


def run_self_tests(
    lmdebug_bin: pathlib.Path,
    lmssl_bin: pathlib.Path,
    compiler_bin: pathlib.Path,
) -> int:
    """Execute the 8 mandatory Slice 3 fixture edge-case tests using lmdebug pcap."""
    env = dict(os.environ)
    env["PATH"] = f"{lmssl_bin.parent}:{lmdebug_bin.parent}:{env.get('PATH', '')}"

    def dissect_lms_snippet(td_p: pathlib.Path, body: str) -> list[dict[str, Any]]:
        lms = td_p / "case.lms"
        dslb = td_p / "case.dslb"
        csv_out = td_p / "fields.csv"
        fields = (
            "frame.number,frame.time,frame.time_epoch_ns,frame.len,frame.cap_len,"
            "ip.src,ip.dst,ipv6.src,ipv6.dst,tcp.srcport,tcp.dstport,tcp.seq,tcp.ack,"
            "tcp.rel_seq,tcp.rel_ack,tcp.flags,tcp.len,tcp.stream,"
            "tcp.analysis.retransmission,tls.handshake.type,tls.version,tls.sni,"
            "tls.alpn,tls.cipher_suite,frame.info"
        )
        lms.write_text(
            f'''p = _lmcode_ cli="lmdebug pcap";
let cap = shark.capture();
{body}
cap.save_pcapng("{(td_p / 'case.pcapng').as_posix()}");
let reopened = shark.open("{(td_p / 'case.pcapng').as_posix()}");
reopened.save_fields_csv("tcp", "{fields}", "{csv_out.as_posix()}");
end _lmcode_
savedsl(p, "{dslb.as_posix()}");
''',
            encoding="utf-8",
        )
        subprocess.run([str(compiler_bin), str(lms)], env=env, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([str(lmdebug_bin), "pcap", "--lmcode", str(dslb)], env=env, check=True, stdout=subprocess.DEVNULL)
        return load_dissected_fields_csv(csv_out)

    base_manifest = {
        "format_version": 1,
        "mode": "replay_fixture",
        "url": "https://edge.lmctl.ai/test",
        "tuple": {
            "client_ip": "10.0.0.1",
            "client_port": 40000,
            "server_ip": "10.0.0.2",
            "server_port": 443,
            "family": "ipv4",
        },
        "tls": {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "alpn": "http/1.1"},
        "http": {"request_bytes": 64, "response_bytes": 128},
        "timings": {
            "tcp_connect_us": 5000,
            "tls_handshake_us": 10000,
            "request_write_us": 200,
            "ttfb_us": 4000,
            "transfer_us": 100,
            "close_call_us": 100,
            "close_call_kind": "tls_shutdown_attempt",
        },
    }
    minimal_trace = """Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 91
    ClientHello, Length=87
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 65
    ServerHello, Length=61
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 38
  Inner Content Type = Handshake (22)
    EncryptedExtensions, Length=17
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 200
  Inner Content Type = Handshake (22)
    Certificate, Length=179
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 97
  Inner Content Type = Handshake (22)
    CertificateVerify, Length=76
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 53
  Inner Content Type = Handshake (22)
    Finished, Length=32
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 53
  Inner Content Type = Handshake (22)
    Finished, Length=32
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 64
  Inner Content Type = ApplicationData (23)
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 128
  Inner Content Type = ApplicationData (23)
"""

    with tempfile.TemporaryDirectory(prefix="lmdebug-corr-selftest-") as td:
        td_p = pathlib.Path(td)

        # Case 1: Establishing ACK carrying ClientHello data (piggybacked ACK+data)
        rows1 = dissect_lms_snippet(
            td_p,
            '''cap.tcp_segment(0.001, "10.0.0.1", 40000, "10.0.0.2", 443, 1000, 0, "SYN", 64240, "");
cap.tcp_segment(0.002, "10.0.0.2", 443, "10.0.0.1", 40000, 5000, 1001, "SYN,ACK", 65535, "");
# Piggybacked Establishing ACK + ClientHello in packet 3 (98 B, seq 1001..1099)
cap.tls_client_hello(0.003, "10.0.0.1", 40000, "10.0.0.2", 443, 1001, 5001, "edge.lmctl.ai", "1.3", "http/1.1");
cap.tls_server_hello(0.004, "10.0.0.2", 443, "10.0.0.1", 40000, 5001, 1099, "1.3", "http/1.1", 4865);
cap.tls_app_data(0.005, "10.0.0.2", 443, "10.0.0.1", 40000, 5071, 1099, 300);
cap.tls_app_data(0.006, "10.0.0.1", 40000, "10.0.0.2", 443, 1099, 5376, 120);
cap.tls_app_data(0.007, "10.0.0.2", 443, "10.0.0.1", 40000, 5376, 1224, 128);
cap.tcp_close(0.008, "10.0.0.1", 40000, "10.0.0.2", 443, 1224, 5509, 0.002);''',
        )
        c1 = correlate_exchange(rows1, minimal_trace, base_manifest)
        assert c1["ok"], c1
        est_step = next(s for s in c1["steps"] if s["label"] == "TCP Establishing ACK")
        ch_step = next(s for s in c1["steps"] if s["label"] == "ClientHello")
        assert est_step["evidence"] == "exact" and est_step["packet_ids"] == [3], est_step
        assert "carries" in est_step["explanation"], est_step
        assert ch_step["evidence"] == "exact" and ch_step["packet_ids"] == [3], ch_step

        # Case 2: Retransmission is kept as a packet row and not an extra protocol step
        rows2 = dissect_lms_snippet(
            td_p,
            '''cap.tcp_handshake(0.000, "10.0.0.1", 40000, "10.0.0.2", 443, 0.002);
cap.tls_client_hello(0.003, "10.0.0.1", 40000, "10.0.0.2", 443, 1001, 5001, "edge.lmctl.ai", "1.3", "http/1.1");
cap.tls_server_hello(0.004, "10.0.0.2", 443, "10.0.0.1", 40000, 5001, 1099, "1.3", "http/1.1", 4865);
cap.tls_app_data(0.005, "10.0.0.2", 443, "10.0.0.1", 40000, 5071, 1099, 300);
cap.tls_app_data(0.006, "10.0.0.2", 443, "10.0.0.1", 40000, 5071, 1099, 300);
cap.tls_app_data(0.007, "10.0.0.1", 40000, "10.0.0.2", 443, 1099, 5376, 120);
cap.tls_app_data(0.008, "10.0.0.2", 443, "10.0.0.1", 40000, 5376, 1224, 128);''',
        )
        c2 = correlate_exchange(rows2, minimal_trace, base_manifest)
        assert c2["ok"], c2
        retrans_pkts = [p for p in c2["packets"] if p["retransmission"]]
        assert len(retrans_pkts) == 1 and retrans_pkts[0]["packet_id"] == 7, retrans_pkts
        assert len(c2["steps"]) == len(c1["steps"]), (len(c2["steps"]), len(c1["steps"]))

        # Case 3: 32-bit TCP sequence wraparound modulo 2^32
        rows3 = dissect_lms_snippet(
            td_p,
            '''let isn_c = 4294967200;
let isn_s = 4294967100;
cap.tcp_segment(0.001, "10.0.0.1", 40000, "10.0.0.2", 443, isn_c, 0, "SYN", 64240, "");
cap.tcp_segment(0.002, "10.0.0.2", 443, "10.0.0.1", 40000, isn_s, isn_c + 1, "SYN,ACK", 65535, "");
cap.tcp_segment(0.003, "10.0.0.1", 40000, "10.0.0.2", 443, isn_c + 1, isn_s + 1, "ACK", 64240, "");
# ClientHello crosses 2^32 boundary (4294967201 + 98 = 3 mod 2^32)
cap.tls_client_hello(0.004, "10.0.0.1", 40000, "10.0.0.2", 443, isn_c + 1, isn_s + 1, "edge.lmctl.ai", "1.3", "http/1.1");
cap.tls_server_hello(0.005, "10.0.0.2", 443, "10.0.0.1", 40000, isn_s + 1, 3, "1.3", "http/1.1", 4865);
# Server encrypted flight wraps past 2^32 (4294967171 + 305 = 180 mod 2^32)
cap.tls_app_data(0.006, "10.0.0.2", 443, "10.0.0.1", 40000, isn_s + 71, 3, 300);
# Client encrypted flight starts at wrapped seq 3 (3 + 125 = 128)
cap.tls_app_data(0.007, "10.0.0.1", 40000, "10.0.0.2", 443, 3, 180, 120);
cap.tls_app_data(0.008, "10.0.0.2", 443, "10.0.0.1", 40000, 180, 128, 128);''',
        )
        c3 = correlate_exchange(rows3, minimal_trace, base_manifest)
        assert c3["ok"] and c3["completeness"]["complete_handshake"], c3
        ee_step = next(s for s in c3["steps"] if s["label"] == "EncryptedExtensions")
        assert ee_step["seq_range"] == "4294967171..180", ee_step

        # Case 4: Split ClientHello across two segments & coalesced ServerHello+EncryptedExtensions
        rows4 = dissect_lms_snippet(
            td_p,
            '''cap.tcp_handshake(0.000, "10.0.0.1", 40000, "10.0.0.2", 443, 0.002);
cap.tls_client_hello(0.003, "10.0.0.1", 40000, "10.0.0.2", 443, 1001, 5001, "edge.lmctl.ai", "1.3", "http/1.1");
cap.tcp_segment(0.0035, "10.0.0.1", 40000, "10.0.0.2", 443, 1099, 5001, "PSH,ACK", 64240, "EXTRA-CH-BYTES");
cap.tls_server_hello(0.004, "10.0.0.2", 443, "10.0.0.1", 40000, 5001, 1113, "1.3", "http/1.1", 4865);
cap.tls_app_data(0.006, "10.0.0.1", 40000, "10.0.0.2", 443, 1113, 5071, 120);''',
        )
        split_coalesced_trace = minimal_trace.replace("Length = 65\n    ServerHello, Length=61", "Length = 40\n    ServerHello, Length=36")
        c4 = correlate_exchange(rows4, split_coalesced_trace, base_manifest)
        assert c4["ok"], c4
        ch4 = next(s for s in c4["steps"] if s["label"] == "ClientHello")
        sh4 = next(s for s in c4["steps"] if s["label"] == "ServerHello")
        assert ch4["evidence"] == "flight" and ch4["packet_ids"] == [] and ch4["candidate_packet_ids"] == [4, 5], ch4
        assert sh4["evidence"] == "flight" and sh4["packet_ids"] == [] and 6 in sh4["candidate_packet_ids"], sh4

        # Case 5: Encrypted flight ambiguity (server handshake and server app data not separated by client flight)
        rows5 = dissect_lms_snippet(
            td_p,
            '''cap.tcp_handshake(0.000, "10.0.0.1", 40000, "10.0.0.2", 443, 0.002);
cap.tls_client_hello(0.003, "10.0.0.1", 40000, "10.0.0.2", 443, 1001, 5001, "edge.lmctl.ai", "1.3", "http/1.1");
cap.tls_server_hello(0.004, "10.0.0.2", 443, "10.0.0.1", 40000, 5001, 1099, "1.3", "http/1.1", 4865);
cap.tls_app_data(0.005, "10.0.0.2", 443, "10.0.0.1", 40000, 5071, 1099, 300);
cap.tls_app_data(0.006, "10.0.0.2", 443, "10.0.0.1", 40000, 5376, 1099, 200);''',
        )
        c5 = correlate_exchange(rows5, minimal_trace, base_manifest)
        assert c5["ok"], c5
        ee5 = next(s for s in c5["steps"] if s["label"] == "EncryptedExtensions")
        resp5 = next(s for s in c5["steps"] if s["label"] == "HTTP Response")
        assert ee5["evidence"] == "ambiguous" and ee5["packet_ids"] == [], ee5
        assert resp5["evidence"] == "ambiguous" and resp5["packet_ids"] == [], resp5

        # Case 6: Missing SYN and missing FIN teardown
        rows6 = dissect_lms_snippet(
            td_p,
            '''cap.tls_client_hello(0.010, "10.0.0.1", 40000, "10.0.0.2", 443, 1001, 5001, "edge.lmctl.ai", "1.3", "http/1.1");
cap.tls_server_hello(0.015, "10.0.0.2", 443, "10.0.0.1", 40000, 5001, 1086, "1.3", "http/1.1", 4865);
cap.tls_app_data(0.020, "10.0.0.2", 443, "10.0.0.1", 40000, 5083, 1086, 300);''',
        )
        c6 = correlate_exchange(rows6, minimal_trace, base_manifest)
        assert c6["ok"], c6
        assert c6["completeness"]["has_syn"] is False and c6["completeness"]["has_fin_teardown"] is False, c6["completeness"]
        syn6 = next(s for s in c6["steps"] if s["label"] == "TCP SYN")
        fin6 = next(s for s in c6["steps"] if s["label"] == "TCP Teardown (FIN/RST)")
        assert syn6["evidence"] == "missing" and fin6["evidence"] == "missing", (syn6, fin6)
        assert c6["timings"]["disconnect_us"] is None, c6["timings"]

        # Case 7: Tuple mismatch refusal
        bad_tuple_manifest = json.loads(json.dumps(base_manifest))
        bad_tuple_manifest["tuple"]["client_port"] = 55555
        c7 = correlate_exchange(rows6, minimal_trace, bad_tuple_manifest)
        assert not c7["ok"] and c7["status"] == "tuple_mismatch", c7

        # Case 8: Unsupported TLS 1.2 profile refusal
        tls12_manifest = json.loads(json.dumps(base_manifest))
        tls12_manifest["tls"]["version"] = "TLSv1.2"
        c8 = correlate_exchange(rows1, minimal_trace, tls12_manifest)
        assert not c8["ok"] and c8["status"] == "unsupported_profile", c8

    print("self-test: all 8 Slice-3 correlation edge cases passed")
    return 0


def check_linux_capture_privilege(lmdebug_bin: pathlib.Path, compiler_bin: pathlib.Path) -> tuple[bool, str]:
    """Return (capable, message) for Linux live packet capture."""
    if getattr(os, "geteuid", lambda: -1)() == 0:
        return True, "root"
    status_p = pathlib.Path("/proc/self/status")
    if status_p.is_file():
        for line in status_p.read_text(encoding="utf-8").splitlines():
            if line.startswith("CapEff:"):
                cap_eff = int(line.split()[1], 16)
                if cap_eff & (1 << 13):
                    return True, "process CapEff CAP_NET_RAW"
                break
    # Also probe the lmdebug binary itself in case file capabilities (setcap cap_net_raw=eip) are set on it
    env = dict(os.environ)
    env["PATH"] = f"{lmdebug_bin.parent}:{env.get('PATH', '')}"
    with tempfile.TemporaryDirectory(prefix="lmdebug-cap-probe-") as td:
        td_p = pathlib.Path(td)
        lms = td_p / "probe.lms"
        dslb = td_p / "probe.dslb"
        lms.write_text(
            f'p = _lmcode_ cli="lmdebug pcap";\nlet c = shark.live("lo", 1, 0.1, 65535, false, true, "tcp port 65534");\nend _lmcode_\nsavedsl(p, "{dslb.as_posix()}");\n',
            encoding="utf-8",
        )
        subprocess.run([str(compiler_bin), str(lms)], env=env, check=True, stdout=subprocess.DEVNULL)
        cp = subprocess.run([str(lmdebug_bin), "pcap", "--lmcode", str(dslb)], env=env, capture_output=True, text=True, timeout=5)
        if cp.returncode == 0:
            return True, "lmdebug binary file capability CAP_NET_RAW"
        return False, (cp.stderr or cp.stdout).strip()


def discover_interfaces(
    lmdebug_bin: pathlib.Path,
    compiler_bin: pathlib.Path,
    precompiled_dslb: pathlib.Path | None = None,
) -> list[dict[str, Any]]:
    """Query shark.interfaces() via lmdebug pcap."""
    env = dict(os.environ)
    env["PATH"] = f"{lmdebug_bin.parent}:{env.get('PATH', '')}"
    with tempfile.TemporaryDirectory(prefix="lmdebug-ifaces-") as td:
        td_p = pathlib.Path(td)
        out_txt = td_p / "ifaces.txt"
        if precompiled_dslb and precompiled_dslb.is_file():
            cp = subprocess.run(
                [str(lmdebug_bin), "pcap", "--lmcode", str(precompiled_dslb)],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            lines = cp.stdout.splitlines()
        else:
            lms = td_p / "ifaces.lms"
            dslb = td_p / "ifaces.dslb"
            lms.write_text(
                f'''p = _lmcode_ cli="lmdebug pcap";
let xs = shark.interfaces();
for (i in range(0, xs.len())) {{
    let d = xs.at(i);
    print(d.name() + "|" + str(d.up()) + "|" + str(d.loopback()) + "|" + d.addresses());
}}
end _lmcode_
savedsl(p, "{dslb.as_posix()}");
''',
                encoding="utf-8",
            )
            subprocess.run([str(compiler_bin), str(lms)], env=env, check=True, stdout=subprocess.DEVNULL)
            cp = subprocess.run(
                [str(lmdebug_bin), "pcap", "--lmcode", str(dslb)],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            lines = cp.stdout.splitlines()
        ifaces: list[dict[str, Any]] = []
        for ln in lines:
            parts = ln.strip().split("|", 3)
            if len(parts) != 4:
                continue
            addrs = [a.strip() for a in parts[3].split(",") if a.strip()]
            ifaces.append({
                "name": parts[0],
                "up": parts[1] == "true",
                "loopback": parts[2] == "true",
                "addresses": addrs,
            })
        return ifaces


def select_egress_interface(
    selected_ip: str,
    port: int,
    ifaces: list[dict[str, Any]],
    override_iface: str = "",
) -> tuple[str, str]:
    """Select egress capture interface via UDP route probe + shark.interfaces() matching."""
    if override_iface:
        return override_iface, ""
    ip_obj = ipaddress.ip_address(selected_ip)
    fam = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.connect((selected_ip, port))
        local_ip = s.getsockname()[0]
    if ipaddress.ip_address(local_ip).is_loopback:
        for iface in ifaces:
            if iface["loopback"]:
                return iface["name"], local_ip
        return "lo", local_ip
    for iface in ifaces:
        if local_ip in iface["addresses"]:
            return iface["name"], local_ip
    for iface in ifaces:
        if iface["up"] and not iface["loopback"]:
            return iface["name"], local_ip
    return (ifaces[0]["name"] if ifaces else "lo"), local_ip


def run_live_capture_workflow(
    *,
    raw_url: str,
    out_dir: pathlib.Path,
    lmdebug_bin: pathlib.Path,
    lmssl_bin: pathlib.Path,
    compiler_bin: pathlib.Path,
    iface_override: str = "",
    ca_file: str = "",
    connect_ip_override: str = "",
    capture_duration_sec: float = 25.0,
    startup_margin_sec: float = 1.0,
    allow_skip_unprivileged: bool = False,
    precompiled_ifaces_dslb: pathlib.Path | None = None,
) -> int:
    """Execute the 9-step Live Execution Contract (§2.1) for a single HTTPS attempt."""
    url_info = validate_https_url(raw_url)
    env = dict(os.environ)
    env["PATH"] = f"{lmssl_bin.parent}:{lmdebug_bin.parent}:{env.get('PATH', '')}"

    # Step 2: Preflight tool & schema checks
    lmdebug_ver = subprocess.check_output([str(lmdebug_bin), "pcap", "--version"], text=True).strip()
    lmdebug_schema = subprocess.check_output([str(lmdebug_bin), "pcap", "--lmcode-schema", "--json"])
    lmssl_ver = subprocess.check_output([str(lmssl_bin), "--version"], text=True).strip()
    lmssl_schema = subprocess.check_output([str(lmssl_bin), "--lmcode-schema", "--json"])
    if b'"monotonic_us"' not in lmssl_schema:
        raise RuntimeError("Staged lmssl binary does not expose ssl.monotonic_us() in its schema")

    ifaces = discover_interfaces(lmdebug_bin, compiler_bin, precompiled_ifaces_dslb)
    if not ifaces:
        raise RuntimeError("shark.interfaces() returned an empty interface list")

    capable, cap_msg = check_linux_capture_privilege(lmdebug_bin, compiler_bin)
    if not capable:
        if allow_skip_unprivileged:
            print(
                f"SKIP: live packet correlation capture requires root or CAP_NET_RAW ({cap_msg})"
            )
            return 0
        print(
            f"ERROR: live packet capture requires root or CAP_NET_RAW on lmdebug ({cap_msg})",
            file=sys.stderr,
        )
        return 2

    # Step 3: Untimed preflight DNS resolution & egress interface selection
    t_dns0 = time.monotonic_ns()
    if connect_ip_override:
        selected_ip = connect_ip_override
    elif url_info["is_ip_literal"]:
        selected_ip = url_info["host"]
    else:
        infos = socket.getaddrinfo(url_info["host"], url_info["port"], type=socket.SOCK_STREAM)
        if not infos:
            raise RuntimeError(f"DNS resolution returned no addresses for {url_info['host']}")
        selected_ip = infos[0][4][0]
    dns_us = int(round((time.monotonic_ns() - t_dns0) / 1000.0))

    ip_obj = ipaddress.ip_address(selected_ip)
    family = "ipv6" if ip_obj.version == 6 else "ipv4"
    iface, route_src_ip = select_egress_interface(selected_ip, url_info["port"], ifaces, iface_override)
    bpf_filter = f"host {selected_ip} and tcp port {url_info['port']}"

    out_dir.mkdir(parents=True, exist_ok=True)
    pcapng_path = out_dir / "capture.pcapng"
    fields_csv_path = out_dir / "dissected_fields.csv"
    trace_path = out_dir / "tls-trace.txt"
    hs_trace_path = out_dir / "tls-trace-handshake.txt"
    client_meta_path = out_dir / "client_metrics.json"

    fields_spec = (
        "frame.number,frame.time,frame.time_epoch_ns,frame.len,frame.cap_len,"
        "ip.src,ip.dst,ipv6.src,ipv6.dst,tcp.srcport,tcp.dstport,tcp.seq,tcp.ack,"
        "tcp.rel_seq,tcp.rel_ack,tcp.flags,tcp.len,tcp.stream,"
        "tcp.analysis.retransmission,tls.handshake.type,tls.version,tls.sni,"
        "tls.alpn,tls.cipher_suite,frame.info"
    )

    with tempfile.TemporaryDirectory(prefix="lmdebug-corr-live-") as td:
        td_p = pathlib.Path(td)
        cap_lms = td_p / "capture.lms"
        cap_dslb = td_p / "capture.dslb"
        cap_lms.write_text(
            f'''p = _lmcode_ cli="lmdebug pcap";
let cap = shark.live("{iface}", 100000, {capture_duration_sec:.2f}, 65535, false, true, "{bpf_filter}");
cap.save_pcapng("{pcapng_path.as_posix()}");
cap.save_fields_csv("tcp", "{fields_spec}", "{fields_csv_path.as_posix()}");
end _lmcode_
savedsl(p, "{cap_dslb.as_posix()}");
''',
            encoding="utf-8",
        )
        subprocess.run([str(compiler_bin), str(cap_lms)], env=env, check=True, stdout=subprocess.DEVNULL)

        ca_clause = f'.ca_file("{ca_file}")' if ca_file else ".system_roots()"
        req_str = (
            f"GET {url_info['path']} HTTP/1.1\\r\\n"
            f"Host: {url_info['host_header']}\\r\\n"
            f"User-Agent: lmdebug-correlation/1.0\\r\\n"
            f"Accept: */*\\r\\n"
            f"Connection: close\\r\\n\\r\\n"
        )
        client_lms = td_p / "client.lms"
        client_dslb = td_p / "client.dslb"
        client_lms.write_text(
            f'''p = _lmcode_ cli="lmssl";
net.timeout(15000);
let t0 = ssl.monotonic_us();
let conn = net.connect("{selected_ip}", {url_info["port"]});
let t_conn = ssl.monotonic_us();
let local_ep = conn.local();
let peer_ep = conn.peer();

let ctx = ssl.client_ctx(){ca_clause}.min_version("TLSv1.3").max_version("TLSv1.3").alpn("http/1.1").trace(true);
let tls = ctx.connect(conn, "{url_info["host"]}");
let t_tls = ssl.monotonic_us();
let hs_trace = tls.trace();

let req = "{req_str}";
let nw = tls.write(req);
let t_write = ssl.monotonic_us();

let first_b = tls.read(1);
let t_ttfb = ssl.monotonic_us();
let rest_b = tls.read_all(1048576);
let t_transfer = ssl.monotonic_us();
let eof_b = tls.read(1);
let t_eof = ssl.monotonic_us();

tls.shutdown();
let t_close = ssl.monotonic_us();
conn.close();
let t_end = ssl.monotonic_us();

fs.write("{hs_trace_path.as_posix()}", hs_trace);
fs.write("{trace_path.as_posix()}", tls.trace());
let total_resp = str_len(first_b) + str_len(rest_b);
let meta = "{{\\n"
    + "  \\"local\\": \\"" + local_ep + "\\",\\n"
    + "  \\"peer\\": \\"" + peer_ep + "\\",\\n"
    + "  \\"tls_version\\": \\"" + tls.version() + "\\",\\n"
    + "  \\"tls_cipher\\": \\"" + tls.cipher() + "\\",\\n"
    + "  \\"tls_group\\": \\"" + tls.group() + "\\",\\n"
    + "  \\"tls_alpn\\": \\"" + tls.alpn() + "\\",\\n"
    + "  \\"tls_verified\\": " + str(tls.verified()) + ",\\n"
    + "  \\"tls_verify_result\\": \\"" + tls.verify_result() + "\\",\\n"
    + "  \\"request_bytes\\": " + str(nw) + ",\\n"
    + "  \\"response_bytes\\": " + str(total_resp) + ",\\n"
    + "  \\"t0\\": " + str(t0) + ",\\n"
    + "  \\"t_conn\\": " + str(t_conn) + ",\\n"
    + "  \\"t_tls\\": " + str(t_tls) + ",\\n"
    + "  \\"t_write\\": " + str(t_write) + ",\\n"
    + "  \\"t_ttfb\\": " + str(t_ttfb) + ",\\n"
    + "  \\"t_transfer\\": " + str(t_transfer) + ",\\n"
    + "  \\"t_eof\\": " + str(t_eof) + ",\\n"
    + "  \\"t_close\\": " + str(t_close) + ",\\n"
    + "  \\"t_end\\": " + str(t_end) + "\\n"
    + "}}\\n";
fs.write("{client_meta_path.as_posix()}", meta);
end _lmcode_
savedsl(p, "{client_dslb.as_posix()}");
''',
            encoding="utf-8",
        )
        subprocess.run([str(compiler_bin), str(client_lms)], env=env, check=True, stdout=subprocess.DEVNULL)

        # Step 4: Start capture child process
        cap_proc = subprocess.Popen(
            [str(lmdebug_bin), "pcap", "--lmcode", str(cap_dslb)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            # Step 5: Bounded startup margin (not a readiness proof)
            time.sleep(startup_margin_sec)
            if cap_proc.poll() is not None:
                out_s, err_s = cap_proc.communicate()
                raise RuntimeError(f"Capture child exited early ({cap_proc.returncode}): {err_s or out_s}")

            # Step 6: Run measured HTTPS request
            client_cp = subprocess.run(
                [str(lmssl_bin), "--lmcode", str(client_dslb)],
                env=env,
                capture_output=True,
                text=True,
                timeout=20.0,
            )
            if client_cp.returncode != 0:
                raise RuntimeError(f"lmssl client failed ({client_cp.returncode}): {client_cp.stderr or client_cp.stdout}")
        finally:
            # Step 7: Wait up to 35s supervisor deadline for capture completion
            try:
                cap_proc.wait(timeout=35.0)
            except subprocess.TimeoutExpired:
                cap_proc.terminate()
                try:
                    cap_proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    cap_proc.kill()
                    cap_proc.wait()
                raise RuntimeError("Capture subprocess exceeded 35s supervisor deadline")

    cmeta = json.loads(client_meta_path.read_text(encoding="utf-8"))
    c_ip, c_port = parse_endpoint(cmeta["local"])
    s_ip, s_port = parse_endpoint(cmeta["peer"])

    t0 = int(cmeta["t0"])
    tcp_connect_us = int(cmeta["t_conn"]) - t0
    tls_handshake_us = int(cmeta["t_tls"]) - int(cmeta["t_conn"])
    request_write_us = int(cmeta["t_write"]) - int(cmeta["t_tls"])
    ttfb_us = int(cmeta["t_ttfb"]) - int(cmeta["t_write"]) if int(cmeta["response_bytes"]) > 0 else None
    transfer_us = int(cmeta["t_transfer"]) - int(cmeta["t_ttfb"]) if int(cmeta["response_bytes"]) > 0 else None
    eof_us = int(cmeta["t_eof"]) - int(cmeta["t_transfer"])
    close_call_us = int(cmeta["t_close"]) - int(cmeta["t_eof"])
    total_us = int(cmeta["t_end"]) - t0
    accounted_us = (
        tcp_connect_us
        + tls_handshake_us
        + request_write_us
        + (ttfb_us or 0)
        + (transfer_us or 0)
        + eof_us
        + close_call_us
    )
    residual_us = max(0, total_us - accounted_us)

    manifest = {
        "format_version": FORMAT_VERSION,
        "mode": "measured",
        "synthetic_capture": False,
        "synthetic_timings": False,
        "attempt_id": f"live-{int(time.time())}-{c_port}",
        "url": url_info["sanitized_url"],
        "selected_ip": selected_ip,
        "route_source_ip": route_src_ip,
        "preflight_note": "Preflight DNS resolution and UDP route probe ran before capture startup.",
        "tuple": {
            "client_ip": c_ip,
            "client_port": c_port,
            "server_ip": s_ip,
            "server_port": s_port,
            "family": family,
        },
        "capture": {
            "interface": iface,
            "bpf_filter": bpf_filter,
            "snaplen": 65535,
            "packet_limit": 100000,
            "duration_sec": capture_duration_sec,
            "startup_margin_sec": startup_margin_sec,
            "startup_margin_note": (
                "Startup delay is an engineering margin, not a kernel readiness proof; "
                "SYN/SYN-ACK/ACK presence is verified directly from captured packets."
            ),
        },
        "tools": {
            "lmdebug_pcap_version": lmdebug_ver,
            "lmdebug_pcap_schema_sha256": sha256_bytes(lmdebug_schema),
            "lmssl_version": lmssl_ver,
            "lmssl_schema_sha256": sha256_bytes(lmssl_schema),
        },
        "tls": {
            "version": cmeta["tls_version"],
            "cipher": cmeta["tls_cipher"],
            "group": cmeta["tls_group"],
            "alpn": cmeta["tls_alpn"],
            "server_name": url_info["host"],
            "verified": bool(cmeta["tls_verified"]),
            "verify_result": cmeta["tls_verify_result"],
        },
        "http": {
            "method": "GET",
            "path": url_info["path"],
            "request_bytes": int(cmeta["request_bytes"]),
            "response_bytes": int(cmeta["response_bytes"]),
        },
        "timings": {
            "dns_us": dns_us,
            "connect_start_us": 0,
            "tcp_connect_us": tcp_connect_us,
            "tls_handshake_us": tls_handshake_us,
            "request_write_us": request_write_us,
            "ttfb_us": ttfb_us,
            "transfer_us": transfer_us,
            "eof_us": eof_us,
            "close_call_us": close_call_us,
            "close_call_kind": "tls_shutdown_attempt",
            "total_us": total_us,
            "accounted_us": accounted_us,
            "residual_us": residual_us,
        },
    }

    trace_text = trace_path.read_text(encoding="utf-8")
    hs_trace_text = hs_trace_path.read_text(encoding="utf-8") if hs_trace_path.is_file() else ""
    rows = load_dissected_fields_csv(fields_csv_path)
    corr = correlate_exchange(rows, trace_text, manifest, hs_trace_text)
    write_correlation_artifacts(out_dir, manifest, trace_text, corr)
    if not corr["ok"]:
        print(f"ERROR: {corr['error']}", file=sys.stderr)
        return 1

    comp = corr["completeness"]
    print(f"mode={manifest['mode']} status={corr['status']} tuple={c_ip}:{c_port}->{s_ip}:{s_port}")
    print(f"packets={len(corr['packets'])} steps={len(corr['steps'])} complete_handshake={str(comp['complete_handshake']).lower()}")
    return 0


def run_loopback_live_self_test(
    *,
    out_dir: pathlib.Path,
    lmdebug_bin: pathlib.Path,
    lmssl_bin: pathlib.Path,
    compiler_bin: pathlib.Path,
    allow_skip_unprivileged: bool = True,
) -> int:
    """Privileged loopback live-capture regression gate (no external Internet needed)."""
    capable, cap_msg = check_linux_capture_privilege(lmdebug_bin, compiler_bin)
    if not capable:
        if allow_skip_unprivileged:
            print(f"SKIP: privileged loopback correlation test requires root or CAP_NET_RAW ({cap_msg})")
            return 0
        print(f"ERROR: privileged loopback test lacks capture permission ({cap_msg})", file=sys.stderr)
        return 2

    env = dict(os.environ)
    env["PATH"] = f"{lmssl_bin.parent}:{lmdebug_bin.parent}:{env.get('PATH', '')}"

    with tempfile.TemporaryDirectory(prefix="lmdebug-corr-loopback-") as td:
        td_p = pathlib.Path(td)
        cert_lms = td_p / "cert.lms"
        cert_dslb = td_p / "cert.dslb"
        cert_lms.write_text(
            f'''p = _lmcode_ cli="lmssl";
let ca_k = ssl.gen_ec("P-256");
let ca = ssl.new_cert(ca_k, "/CN=LoopbackTestCA").ca(true).valid_days(7).sign_self(ca_k, "SHA256");
let sk = ssl.gen_ec("P-256");
let sc = ssl.new_cert(sk, "/CN=localhost").san("DNS:localhost,IP:127.0.0.1").valid_days(7).sign_with(ca, ca_k, "SHA256");
ca.save("{(td_p / 'ca.pem').as_posix()}");
sc.save("{(td_p / 'srv.pem').as_posix()}");
sk.save("{(td_p / 'srv.key').as_posix()}");
end _lmcode_
savedsl(p, "{cert_dslb.as_posix()}");
''',
            encoding="utf-8",
        )
        subprocess.run([str(compiler_bin), str(cert_lms)], env=env, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([str(lmssl_bin), "--lmcode", str(cert_dslb)], env=env, check=True, stdout=subprocess.DEVNULL)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.load_cert_chain(str(td_p / "srv.pem"), str(td_p / "srv.key"))

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def serve() -> None:
            try:
                conn, _ = srv.accept()
                with ctx.wrap_socket(conn, server_side=True) as sconn:
                    sconn.recv(4096)
                    sconn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 15\r\nConnection: close\r\n\r\nloopback-live\r\n"
                    )
                    try:
                        sconn.unwrap()
                    except Exception:
                        pass
            finally:
                srv.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        rc = run_live_capture_workflow(
            raw_url=f"https://localhost:{port}/loopback",
            out_dir=out_dir,
            lmdebug_bin=lmdebug_bin,
            lmssl_bin=lmssl_bin,
            compiler_bin=compiler_bin,
            iface_override="lo",
            ca_file=str(td_p / "ca.pem"),
            connect_ip_override="127.0.0.1",
            capture_duration_sec=2.0,
            startup_margin_sec=0.35,
            allow_skip_unprivileged=allow_skip_unprivileged,
        )
        th.join(timeout=3.0)
        if rc != 0:
            return rc

        steps_doc = json.loads((out_dir / "steps.json").read_text(encoding="utf-8"))
        req_doc = json.loads((out_dir / "request.json").read_text(encoding="utf-8"))
        assert req_doc["completeness"]["complete_handshake"] is True, req_doc["completeness"]
        for s in steps_doc["steps"]:
            if s["label"] in ("EncryptedExtensions", "Certificate", "CertificateVerify", "Server Finished", "Client Finished"):
                assert s["evidence"] != "exact" and s["packet_ids"] == [], s
        print("loopback-self-test: live TCP+TLS1.3 capture and flight correlation verified")
        return 0


def resolve_binary(explicit: str, name: str, fallback_paths: list[str]) -> pathlib.Path:
    if explicit:
        p = pathlib.Path(explicit).resolve()
        if p.is_file():
            return p
    import shutil
    found = shutil.which(name)
    if found:
        return pathlib.Path(found).resolve()
    for fp in fallback_paths:
        p = pathlib.Path(fp).resolve()
        if p.is_file():
            return p
    raise FileNotFoundError(f"Could not locate executable {name!r}")


def main() -> int:
    here = pathlib.Path(__file__).resolve().parent
    repo_root = here.parents[1]

    ap = argparse.ArgumentParser(description="lmdebug x lmssl HTTPS packet-correlation tool")
    ap.add_argument("--offline", action="store_true", help="run offline replay correlation")
    ap.add_argument("--live", action="store_true", help="run live capture + HTTPS request correlation")
    ap.add_argument("--loopback-self-test", action="store_true", help="run privileged loopback live capture self-test")
    ap.add_argument("--self-test", action="store_true", help="run 8 offline edge-case regression checks")
    ap.add_argument("--generate-fixture", action="store_true", help="generate deterministic offline fixtures")
    ap.add_argument("--url", default="", help="target HTTPS URL for --live (default: LMDEBUG_CORR_URL or https://lmctl.com/)")
    ap.add_argument("--iface", default="", help="override capture interface for --live")
    ap.add_argument("--dissected-csv", default="", help="path to dissected_fields.csv from lmdebug pcap")
    ap.add_argument("--fixture-dir", default=str(here / "fixtures"), help="path to offline fixture directory")
    ap.add_argument("--lmssl-verify-json", default="", help="path to lmssl fixture verification JSON")
    ap.add_argument("--out-dir", default="", help="output directory for correlation artifacts")
    ap.add_argument("--host", default="", help="path to lmdebug binary")
    ap.add_argument("--lmssl", default="", help="path to lmssl binary")
    ap.add_argument("--compiler", default="", help="path to lmscript compiler")
    ap.add_argument("--allow-skip", action="store_true", help="skip cleanly when live capture privileges are absent")
    ap.add_argument("--ifaces-dslb", default="", help="precompiled shark.interfaces() bytecode")
    args = ap.parse_args()

    lmdebug_bin = resolve_binary(
        args.host,
        "lmdebug",
        [str(repo_root / "build/lmdebug"), "/home/mma/repos/dsl/lmdebug/build/lmdebug"],
    )
    lmssl_bin = resolve_binary(
        args.lmssl,
        "lmssl",
        [str(repo_root.parent / "lmssl/build/lmssl"), "/home/mma/repos/dsl/lmssl/build/lmssl"],
    )
    compiler_default = ""
    sel_script = repo_root / "scripts/select-compiler.sh"
    if sel_script.is_file():
        compiler_default = subprocess.check_output([str(sel_script)], text=True).strip()
    compiler_bin = resolve_binary(args.compiler or compiler_default, "lmscript", [])

    if args.generate_fixture:
        build_deterministic_fixture(pathlib.Path(args.fixture_dir), lmdebug_bin, lmssl_bin, compiler_bin)
        print(f"generated deterministic fixtures in {args.fixture_dir}")
        return 0

    if args.self_test:
        return run_self_tests(lmdebug_bin, lmssl_bin, compiler_bin)

    if args.loopback_self_test:
        out_d = pathlib.Path(args.out_dir or (repo_root / "build/examples/correlation/loopback"))
        return run_loopback_live_self_test(
            out_dir=out_d,
            lmdebug_bin=lmdebug_bin,
            lmssl_bin=lmssl_bin,
            compiler_bin=compiler_bin,
            allow_skip_unprivileged=args.allow_skip,
        )

    if args.live:
        out_d = pathlib.Path(args.out_dir or (repo_root / "build/examples/correlation/live"))
        url_file = out_d / "target_url.txt"
        raw_url = (
            args.url
            or os.environ.get("LMDEBUG_CORR_URL", "")
            or (url_file.read_text(encoding="utf-8").strip() if url_file.is_file() else "")
            or "https://lmctl.com/"
        )
        return run_live_capture_workflow(
            raw_url=raw_url,
            out_dir=out_d,
            lmdebug_bin=lmdebug_bin,
            lmssl_bin=lmssl_bin,
            compiler_bin=compiler_bin,
            iface_override=args.iface or os.environ.get("LMDEBUG_CORR_IFACE", ""),
            allow_skip_unprivileged=args.allow_skip,
            precompiled_ifaces_dslb=pathlib.Path(args.ifaces_dslb) if args.ifaces_dslb else None,
        )

    if args.offline:
        out_d = pathlib.Path(args.out_dir or (repo_root / "build/examples/correlation/offline"))
        return run_offline_correlation(
            dissected_csv=pathlib.Path(args.dissected_csv),
            fixture_dir=pathlib.Path(args.fixture_dir),
            lmssl_verify_json=pathlib.Path(args.lmssl_verify_json),
            out_dir=out_d,
            lmdebug_bin=lmdebug_bin,
            lmssl_bin=lmssl_bin,
        )

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
