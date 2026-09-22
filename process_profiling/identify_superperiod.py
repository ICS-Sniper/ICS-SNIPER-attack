
#!/usr/bin/env python3
# Requirements: pyshark, scikit-learn and tshark

import argparse
from ltsutils import *
import pyshark
from collections import defaultdict
from sklearn.cluster import KMeans
import numpy as np
from traffic_processing import *
import pickle
from typing import List, Tuple, Union
import math
import matplotlib.pyplot as plt
from burst_analysis import *
from superperiod_diff import *
import os


def parse_arguments() -> Tuple[str, str, str]:
    """
    Parse command-line arguments.
    Returns:
        Tuple containing pcap file path and IP address.
    """
    parser = argparse.ArgumentParser(description="Process OpenVPN traffic from pcap.")
    parser.add_argument("pcap_file", help="Path to the input pcap file")
    parser.add_argument("ip_compromised", help="IP address of compromised router")
    args = parser.parse_args()
    print("Parsed all input arguments")
    # return args.pcap_file, args.ip_address_1, args.ip_address_2, args.ip_compromised
    return args.pcap_file, args.ip_compromised

def detect_protocol(packets_by_ip: dict) -> dict:
    """
    Identify whether the protocol is connected or unconnected

    Args:
        packets_by_ip: dict where keys are IP addresses and values are lists of
                       packet tuples. Modified in-place to keep only the top 2 IPs.

    Returns:
        dict with keys:
            - "ip_plc"        : IP address designated as the PLC
            - "ip_scada"      : IP address designated as the SCADA system
            - "protocol"      : Detected protocol ("Connected" or "Unconnected")
            - "packet_counts" : {ip: count} for the top 2 IPs
    """

    # ------------------------------------------------------------------ #
    # Step 1: Count packets per IP and select top 2                       #
    # ------------------------------------------------------------------ #

    counts = {ip: len(pkts) for ip, pkts in packets_by_ip.items()}
    top2   = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:2]

    if len(top2) < 2:
        raise ValueError(f"Need at least 2 IP addresses, found {len(top2)}.")

    # Remove all IPs that are not in the top 2 (in-place)
    top2_ips = {ip for ip, _ in top2}
    for ip in list(packets_by_ip.keys()):
        if ip not in top2_ips:
            del packets_by_ip[ip]

    # ip_x = smaller sender, ip_y = larger sender
    ip_y, count_y = top2[0]   # larger
    ip_x, count_x = top2[1]   # smaller

    # ------------------------------------------------------------------ #
    # Step 2: Classify protocol by y:x ratio                             #
    # ------------------------------------------------------------------ #

    ratio = count_y / count_x  # 1.0 = equal, 1.5 = ENIP

    # Midpoint between 1.0 and 1.5 is 1.25 — use as the boundary
    RATIO_THRESHOLD = 1.1

    if ratio < RATIO_THRESHOLD:
        # ratio close to 1.0 → Unconnected
        # First sender chronologically = PLC, second = SCADA
        protocol = "Unconnected"
        first_ts_y = packets_by_ip[ip_y][0][1]  # timestamp of first packet from ip_y
        first_ts_x = packets_by_ip[ip_x][0][1]  # timestamp of first packet from ip_x
        if first_ts_y <= first_ts_x:
            ip_plc, ip_scada = ip_y, ip_x
        else:
            ip_plc, ip_scada = ip_x, ip_y
    else:
        # ratio close to 1.5 → Connected
        # Larger sender = PLC, smaller sender = SCADA
        protocol = "Connected"
        ip_plc, ip_scada = ip_y, ip_x

    # ------------------------------------------------------------------ #
    # Step 3: Build and return result                                     #
    # ------------------------------------------------------------------ #

    result = {
        "ip_plc":        ip_plc,
        "ip_scada":      ip_scada,
        "protocol":      protocol,
        "packet_counts": dict(top2),
    }

    # print(f"[detect_protocol] Packet counts : {dict(top2)}")
    # print(f"[detect_protocol] y:x ratio     : {ratio:.3f}")
    # print(f"[detect_protocol] Protocol      : {protocol}")
    print(f"[detect_protocol] PLC           : {ip_plc}  ({counts[ip_plc]} pkts)")
    print(f"[detect_protocol] SCADA         : {ip_scada} ({counts[ip_scada]} pkts)")

    return result

def process_pcap(pcap_file: str, ip_compromised: str) -> dict:
    """
    Processes the pcap file and extract OpenVPN payload sizes and inter-packet timings.
    Args:
        pcap_file: Path to the input pcap file.
        ip_address: IP address to filter OpenVPN traffic.
    Returns:
        A dictionary, where the key is an IP address and the value is a list of tuples(payload size(s), time delta with previous packet).
    """
    print("Starting pcap processing")

    display_filter = f"openvpn and ip.dst=={ip_compromised} && (!(tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.out_of_order || tcp.analysis.spurious_retransmission || tcp.analysis.keep_alive || tcp.analysis.window_update))"

    cap = pyshark.FileCapture(pcap_file, display_filter=display_filter, keep_packets=False)

    packet_counts = defaultdict(int)   # src_ip -> total packets sent to target
    first_seen = {}                    # src_ip -> index of first packet seen
    packet_sequences = defaultdict(list)

    prev_time = None
    start_ts = -99

    try:
        for pkt_index, pkt in enumerate(cap):
            try:
                size = extract_payload_sizes(pkt)
                timestamp = float(pkt.sniff_timestamp)
                ipsrc = pkt.ip.src
                packet_counts[ipsrc] += 1

                ack_rtt = -99
                ack_frame = -99
                protocol = pkt.highest_layer

                if start_ts == -99:
                    start_ts = timestamp
                    timestamp = 0
                else:
                    timestamp = timestamp - start_ts
                    if timestamp > 14400: #operational cycle length: 4 hours
                        break

                if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'analysis_ack_rtt'):
                    ack_rtt = pkt.tcp.analysis_ack_rtt
                    ack_frame = pkt.tcp.analysis_acks_frame


                for s in size:
                    if s>0:
                            packet_sequences[ipsrc].append((s, timestamp, ipsrc, protocol, ack_rtt, ack_frame))

            except AttributeError:
                # Packet has no IP layer (e.g. ARP, raw Ethernet) — skip
                continue
    finally:
        cap.close()
    print("pcap processing completed - Extracted all relevant packet information")
    # print(packet_sequences)
    return packet_sequences



def main():

    pcap_file, ip_compromised = parse_arguments()
    print(pcap_file)
    # print(ip_compromised)

    ############################################################################
    # Step 1: Extract packet lengths and inter-packet time intervals of all packets destined to the compromised ip address
    packets_file = pcap_file.split('.pcap')[0]+'_packets.pkl'
    if os.path.exists(packets_file):
        with open(packets_file, 'rb') as picklefile:
            packets = pickle.load(picklefile)
    else:
        packets = process_pcap(pcap_file, ip_compromised)
        # print(packets)
        with open(packets_file,'wb') as picklefile:
            pickle.dump(packets,picklefile)
    ############################################################################
    # Step 2: superperiod identification

    # Step 2a: Detect endpoint ip addresses and protocol
    endpoints_and_protocol = detect_protocol(packets)

    # Step 2b: Detect superperiods
    print ("Analyzing PLC->router stable regions:\n")
    superperiod, zones = analyze_stable(packets[endpoints_and_protocol['ip_plc']],pcap_file)
    print ("Analyzing SCADA->router IATs:\n")
    superperiod, zones = analyze_stable(packets[endpoints_and_protocol['ip_scada']],pcap_file)

    print ("Analyzing PLC->router IATs:\n")
    superperiod, zones = analyze_iat(packets[endpoints_and_protocol['ip_plc']],pcap_file)
    print ("Analyzing SCADA->router IATs:\n")
    superperiod, zones = analyze_iat(packets[endpoints_and_protocol['ip_scada']],pcap_file)
    print ("Analyzing PLC->router packet sizes:\n")
    superperiod, zones = analyze_sizes(packets[endpoints_and_protocol['ip_plc']])
    print ("Analyzing SCADA->router packet sizes:\n")
    superperiod, zones = analyze_sizes(packets[endpoints_and_protocol['ip_scada']])
    print("\n\n")
    ########################################################################
    # Step 3: Detect state transitions
    # packets_file = pcap_file.split('.pcap')[0]+'_packets.pkl'
    # with open(packets_file, 'rb') as picklefile:
    #     packets = pickle.load(picklefile)

    # analyze_packet_segments(packets[endpoints_and_protocol['ip_plc']],[253,1206,115,113,73,97,100,93,103,85,89,120,83,81,72,109,101,76,91,189],420)
    # analyze_packet_segments(packets[endpoints_and_protocol['ip_plc']],[],180)
    ########################################################################
    # results = detect_superperiod_differences(packets[endpoints_and_protocol['ip_plc']], L= 420) # L needs to be manually configured now. For distinct superperiods with equally high score, perform LCM, else take average
    #
    # print(results)
    # print("Segment with maximum 84-packet count difference:")
    # print(results["max_diff_segment"])
    #
    # print("\nAll segment differences:")
    # ######### Uncomment following block ################
    # for d in results["all_differences"]:
    #     print(f"Seg {d['segment_index']}: "
    #           f"[{d['start_time']:.2f}-{d['end_time']:.2f}]s | "
    #           f"num_packets_diff={d['num_packets_diff']} | "
    #           f"size_set_diff={d['size_set_diff']} | "
    #           f"combined_diff={d['combined_diff']}")
    ############# Uncomment until here ############################

    # debug_zone_counts(packets, zones, L=superperiod)

    # results = detect_superperiod_differences_with_zones(packets, zones, superperiod, ip_address_2)
    #
    # # results = detect_superperiod_differences_with_zones(packets, zones, L=60.0, src_ip="10.0.0.1")
    #
    # for d in results["all_differences"]:
    #     print(f"Seg {d['segment_index']}: [{d['start_time_ms']:.0f}-{d['end_time_ms']:.0f}] ms | "
    #           f"84 diff={d['count_diff']}, zones diff={d['zone_count_diff']}, "
    #           f"zone_dur diff={d['zone_duration_diff_ms']:.1f} ms")

    #######################################################



if __name__ == "__main__":
    main()
