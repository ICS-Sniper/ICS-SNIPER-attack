
#!/usr/bin/env python3
# Requirements: pyshark, scikit-learn and tshark

import argparse
from ltsutils import *
import pyshark
from collections import defaultdict
from sklearn.cluster import KMeans
import numpy as np
# from traffic_processing import *
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
    parser.add_argument("ip_address_1", help="IP address of endpoint#1 to filter OpenVPN traffic")
    parser.add_argument("ip_address_2", help="IP address of endpoint#2 to filter OpenVPN traffic")
    parser.add_argument("superperiod", help="Superperiod determined from Step 1")
    args = parser.parse_args()
    print("Parsed all input arguments")
    # return args.pcap_file, args.ip_address_1, args.ip_address_2, args.ip_compromised
    return args.pcap_file, args.ip_address_1, args.ip_address_2, int(args.superperiod)

def extract_payload_sizes(pkt,ip_address):
    """
    Extract size(s) of OpenVPN payload(s) from the packet.
    Args:
        pkt: The packet to extract payloads from.
    Returns:
        A list of sizes if multiple OpenVPN layers exist, else a single integer.
    """
    sizes = []
    dir_flag = 1
    # if pkt.ip.dst in ip_address:
    #     dir_flag = -1
    # print(pkt.layers)
    if pkt.highest_layer == "OPENVPN":
        length = pkt.openvpn.plen
        if length is not None:
            try:
                sizes.append(dir_flag*int(length))
            except ValueError:
                pass  # skip malformed values
    if pkt.highest_layer == "TCP":
        length = pkt.tcp.len
        if length is not None:
            try:
                sizes.append(dir_flag*int(length))
            except ValueError:
                pass  # skip malformed values

    if not sizes:
        return 0
    # print ("All payload extracted")
    return sizes if len(sizes) > 1 else [sizes[0]]    

def process_pcap(pcap_file: str, ip_address_1: str, ip_address_2: str) -> List[PacketTuple]:
    """
    Processes the pcap file and extract OpenVPN payload sizes and inter-packet timings.
    Args:
        pcap_file: Path to the input pcap file.
        ip_address: IP address to filter OpenVPN traffic.
    Returns:
        A list of tuples: (payload size(s), time delta with previous packet).
    """
    print("Starting pcap processing")
    # actual_filter: openvpn and ip.addr==96.49.203.41&& openvpn.plen>70  && openvpn.plen!=112 && openvpn.plen!=104 && !(ip.dst==96.49.203.41 && openvpn.plen==132) && (!(tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.out_of_order || tcp.analysis.spurious_retransmission || tcp.analysis.keep_alive || tcp.analysis.window_update))
    # display_filter = f"openvpn && ip.addr == {ip_address} && frame.len>=144 && (!(tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.out_of_order || tcp.analysis.spurious_retransmission || tcp.analysis.keep_alive || tcp.analysis.window_update))"
    # display_filter = f"openvpn and ip.addr=={ip_address} && (!(tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.out_of_order || tcp.analysis.spurious_retransmission || tcp.analysis.keep_alive || tcp.analysis.window_update))"
    display_filter = f"tcp and (ip.addr=={ip_address_1}||ip.addr=={ip_address_2}) && (!(tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.out_of_order || tcp.analysis.spurious_retransmission || tcp.analysis.keep_alive || tcp.analysis.window_update))"
    cap = pyshark.FileCapture(pcap_file, display_filter=display_filter, keep_packets=False)

    result = []
    ip_address = [ip_address_1, ip_address_2]
    prev_time = None
    start_ts = -99

    for pkt in cap:
        # print(pkt.layers)
        size = extract_payload_sizes(pkt, ip_address)
        timestamp = float(pkt.sniff_timestamp)
        ipsrc = pkt.ip.src
        ipdst = pkt.ip.dst
        ack_rtt = -99
        ack_frame = -99
        protocol = pkt.highest_layer
        # print(protocol)
        if start_ts == -99:
            start_ts = timestamp
            timestamp = 0
        else:
            timestamp = timestamp - start_ts
            if timestamp > 14400:
                break
        # time_delta = 0.0 if prev_time is None else timestamp - prev_time
        # result.append((size, time_delta))
        if hasattr(pkt.tcp, 'analysis_ack_rtt'):
            ack_rtt = pkt.tcp.analysis_ack_rtt
            ack_frame = pkt.tcp.analysis_acks_frame
        # print(protocol, size)
        if size!=0:
            for s in size:
                if (abs(s)>70 and s!=112 and s!=104 and s!=-132): # Note: Uncomment for enip
                    result.append((s, timestamp, ipsrc, ipdst, protocol, ack_rtt, ack_frame))
        # prev_time = timestamp

    cap.close()
    print("pcap processing completed - Extracted all relevant packet information")
    return result


def main():

    pcap_file, ip_address_1, ip_address_2, superperiod = parse_arguments()
    print(pcap_file)
    # print(ip_compromised)

    ############################################################################
    # Step 1: Extract packet metadata

    packets_file = pcap_file.split('.pcap')[0]+'_packets_1.pkl'

    if os.path.exists(packets_file):
        with open(packets_file, 'rb') as picklefile:
            packets = pickle.load(picklefile)
    else:
        packets = process_pcap(pcap_file, ip_address_1, ip_address_2)
        # print(packets)
        with open(packets_file,'wb') as picklefile:
            pickle.dump(packets,picklefile)


    ############################################################################
    # Step 2: Detect endpoint ip addresses and protocol
    # endpoints_and_protocol = detect_protocol(packets)

    ########################################################################
    # Step 3: Detect state transitions

    # analyze_packet_segments(packets[endpoints_and_protocol['ip_plc']],[253,1206,115,113,73,97,100,93,103,85,89,120,83,81,72,109,101,76,91,189],420)
    # analyze_packet_segments(packets[endpoints_and_protocol['ip_plc']],[],superperiod)
    #######################################################################
    # print(packets[endpoints_and_protocol['ip_plc']])


    results = detect_superperiod_differences(packets, L= superperiod)

    # ######### Uncomment following block ################
    for d in results["all_differences"]:
        print(f"Seg {d['segment_index']}: "
              f"[{d['start_time']:.2f}-{d['end_time']:.2f}]s | "
              f"num_packets_diff={d['num_packets_diff']} | "
              f"size_set_diff={d['size_set_diff']} | "
              f"combined_diff={d['combined_diff']}")

    # results = detect_superperiod_differences(packets[endpoints_and_protocol['ip_scada']], L= superperiod)
    #
    # # ######### Uncomment following block ################
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
