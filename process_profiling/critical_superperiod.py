
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
    parser.add_argument("superperiod", help="Superperiod determined from Step 1")
    args = parser.parse_args()
    print("Parsed all input arguments")
    # return args.pcap_file, args.ip_address_1, args.ip_address_2, args.ip_compromised
    return args.pcap_file, args.ip_compromised, int(args.superperiod)

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
    # print(f"[detect_protocol] PLC           : {ip_plc}  ({counts[ip_plc]} pkts)")
    # print(f"[detect_protocol] SCADA         : {ip_scada} ({counts[ip_scada]} pkts)")

    return result

def main():

    pcap_file, ip_compromised, superperiod = parse_arguments()
    print(pcap_file)
    # print(ip_compromised)

    ############################################################################
    # Step 1: Extract packet lengths and inter-packet time intervals of all packets destined to the compromised ip address
    packets_file = pcap_file.split('.pcap')[0]+'_packets.pkl'
    with open(packets_file, 'rb') as picklefile:
            packets = pickle.load(picklefile)

    ############################################################################
    # Step 2: Detect endpoint ip addresses and protocol
    endpoints_and_protocol = detect_protocol(packets)

    ########################################################################
    # Step 3: Detect state transitions

    # analyze_packet_segments(packets[endpoints_and_protocol['ip_plc']],[253,1206,115,113,73,97,100,93,103,85,89,120,83,81,72,109,101,76,91,189],420)
    # analyze_packet_segments(packets[endpoints_and_protocol['ip_plc']],[],superperiod)
    #######################################################################
    results = detect_superperiod_differences(packets[endpoints_and_protocol['ip_plc']], L= superperiod)

    # ######### Uncomment following block ################
    for d in results["all_differences"]:
        print(f"Seg {d['segment_index']}: "
              f"[{d['start_time']:.2f}-{d['end_time']:.2f}]s | "
              f"num_packets_diff={d['num_packets_diff']} | "
              f"size_set_diff={d['size_set_diff']} | "
              f"combined_diff={d['combined_diff']}")

    results = detect_superperiod_differences(packets[endpoints_and_protocol['ip_scada']], L= superperiod) 

    # ######### Uncomment following block ################
    for d in results["all_differences"]:
        print(f"Seg {d['segment_index']}: "
              f"[{d['start_time']:.2f}-{d['end_time']:.2f}]s | "
              f"num_packets_diff={d['num_packets_diff']} | "
              f"size_set_diff={d['size_set_diff']} | "
              f"combined_diff={d['combined_diff']}")
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
