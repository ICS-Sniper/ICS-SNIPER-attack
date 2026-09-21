#!/usr/bin/env python3
"""

Inspect TCP/1194 packets from netfilter NFQUEUE and drop any packet that
contains an OpenVPN 2-byte-length-framed segment equal to TARGET_SEG_LEN.

Usage:
  sudo python3 nfqueue_drop.py
"""

import struct
import socket
from netfilterqueue import NetfilterQueue

# Configuration
QUEUE_NUM = 1              # must match iptables --queue-num
# TARGET_SEG_LEN = 76        # segment length (in bytes) that triggers a DROP
TARGET_SEG_LEN = 72        # for Modbus
MAX_SEGMENTS = 8           # max number of framed segments to scan per packet
MAX_SEG_LEN = 1400         # sanity upper bound for a segment (prevents DoS parsing)
SOURCE_IP = socket.inet_aton("128.189.240.15")  # <-- hardcode PLC IP here

# NEW: once True, all packets from SOURCE_IP are dropped
dropping = False

def parse_ipv4_header(pkt_bytes):
    # pkt_bytes starts at IPv4 header (as delivered by NFQUEUE)
    if len(pkt_bytes) < 20:
        return None
    ver_ihl = pkt_bytes[0]
    ihl = (ver_ihl & 0x0F) * 4
    if len(pkt_bytes) < ihl:
        return None
    total_len = struct.unpack_from("!H", pkt_bytes, 2)[0]
    proto = pkt_bytes[9]
    src = pkt_bytes[12:16]
    dst = pkt_bytes[16:20]
    return {
        "ihl": ihl,
        "total_len": total_len,
        "proto": proto,
        "src": src,
        "dst": dst,
        "hdr_len": ihl
    }

def parse_tcp_header(pkt_bytes, ip_hdr_len):
    # pkt_bytes starts at IP header; tcp header begins at ip_hdr_len
    start = ip_hdr_len
    if len(pkt_bytes) < start + 20:
        return None
    # Unpack src/dst ports (first 4 bytes of TCP header)
    src_port, dst_port = struct.unpack_from("!HH", pkt_bytes, start)
    # data offset (high 4 bits of byte offset start+12)
    data_offset_byte = pkt_bytes[start + 12]
    data_offset = ((data_offset_byte >> 4) & 0x0F) * 4
    if len(pkt_bytes) < start + data_offset:
        return None
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_hdr_len": data_offset,
        "tcp_start": start
    }

def inspect_openvpn_segments(payload_bytes):
    """
    Walk OpenVPN 2-byte big-endian length framed messages inside payload_bytes.
    Return True if any segment length equals TARGET_SEG_LEN.
    """
    offset = 0
    payload_len = len(payload_bytes)

    # Unroll-like loop up to MAX_SEGMENTS
    for _ in range(MAX_SEGMENTS):
        # need at least 2 bytes for length field
        if offset + 2 > payload_len:
            break

        # read 2-byte big-endian length
        seg_len_be = struct.unpack_from("!H", payload_bytes, offset)[0]
        seg_len = int(seg_len_be)

        # sanity bound
        if seg_len > MAX_SEG_LEN:
            # suspicious or malformed — stop parsing further
            break

        # ensure whole segment fits in payload
        if offset + 2 + seg_len > payload_len:
            break

        # Debug: you can log seg_len here (careful, high-volume)
        # print("seg_len:", seg_len)

        if seg_len == TARGET_SEG_LEN:
            return True

        offset += 2 + seg_len

        if offset >= payload_len:
            break

    return False

def process_packet(nfqueue_pkt):
    """
    NFQueue callback. pkt.get_payload() returns raw IP packet bytes (starting at IPv4 header).
    We inspect and either accept() or drop() the packet.
    """
    pkt_bytes = nfqueue_pkt.get_payload()
    ip_info = parse_ipv4_header(pkt_bytes)
    if not ip_info:
        nfqueue_pkt.accept()
        return

    # Only TCP
    if ip_info["proto"] != 6:
        nfqueue_pkt.accept()
        return

    tcp_info = parse_tcp_header(pkt_bytes, ip_info["hdr_len"])
    if not tcp_info:
        nfqueue_pkt.accept()
        return

    # only target OpenVPN TCP destination port 1194
    if tcp_info["dst_port"] != 1194:
        nfqueue_pkt.accept()
        return

    # compute application payload start and length
    app_start = tcp_info["tcp_start"] + tcp_info["tcp_hdr_len"]
    ip_total_len = ip_info["total_len"]
    # total bytes of payload present (may be less than original if truncated)
    app_payload_len = ip_total_len - ip_info["hdr_len"] - tcp_info["tcp_hdr_len"]

    if app_payload_len <= 0:
        nfqueue_pkt.accept()
        return

    # Safe slice: ensure indexes within pkt_bytes
    if app_start + app_payload_len > len(pkt_bytes):
        # malformed, accept to be conservative
        nfqueue_pkt.accept()
        return

    app_payload = pkt_bytes[app_start:app_start + app_payload_len]

    # Inspect framed OpenVPN segments
    if inspect_openvpn_segments(app_payload):
        # DROP the packet
        print("Dropping packet with OpenVPN segment length", TARGET_SEG_LEN)
        nfqueue_pkt.drop()
        return

    # otherwise accept (let kernel forward/handle it)
    nfqueue_pkt.accept()

def process_packet_modbus(nfqueue_pkt):
    global dropping

    pkt_bytes = nfqueue_pkt.get_payload()
    ip_info = parse_ipv4_header(pkt_bytes)
    if not ip_info:
        nfqueue_pkt.accept()
        return

    if ip_info["proto"] != 6:
        nfqueue_pkt.accept()
        return

    # NEW: if already in drop mode, drop all packets from SOURCE_IP immediately
    if dropping and ip_info["src"] == SOURCE_IP:
        nfqueue_pkt.drop()
        return

    tcp_info = parse_tcp_header(pkt_bytes, ip_info["hdr_len"])
    if not tcp_info:
        nfqueue_pkt.accept()
        return

    if tcp_info["dst_port"] != 1194:
        nfqueue_pkt.accept()
        return

    app_start = tcp_info["tcp_start"] + tcp_info["tcp_hdr_len"]
    ip_total_len = ip_info["total_len"]
    app_payload_len = ip_total_len - ip_info["hdr_len"] - tcp_info["tcp_hdr_len"]

    if app_payload_len <= 0:
        nfqueue_pkt.accept()
        return

    if app_start + app_payload_len > len(pkt_bytes):
        nfqueue_pkt.accept()
        return

    app_payload = pkt_bytes[app_start:app_start + app_payload_len]

    # NEW: only inspect packets from SOURCE_IP; flag and drop on match
    if ip_info["src"] == SOURCE_IP and inspect_openvpn_segments(app_payload):
        print("Triggered: dropping all further packets from SOURCE_IP")
        dropping = True
        nfqueue_pkt.drop()
        return

    nfqueue_pkt.accept()

def main():
    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(QUEUE_NUM, process_packet_modbus, 10000)
        print("Listening on NFQUEUE #%d — target seg len=%d" % (QUEUE_NUM, TARGET_SEG_LEN))
        nfqueue.run()
    except KeyboardInterrupt:
        print("Interrupted, exiting")
    finally:
        try:
            nfqueue.unbind()
        except Exception:
            pass

if __name__ == "__main__":
    main()
