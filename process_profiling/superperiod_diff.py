import numpy as np


# def debug_zone_counts(packets, zones, L):
#     """
#     Debug function: prints how many zones fall into each superperiod segment.
#     Helps diagnose why zone-related differences are all zero.
#     """
#
#     if not packets:
#         raise ValueError("Packets list is empty.")
#     if not zones:
#         raise ValueError("Zones list is empty.")
#
#     # Convert everything to milliseconds for consistency
#     packets = sorted(packets, key=lambda x: x[1])
#     zones = sorted(zones, key=lambda z: z[0])  # zones are in ms
#     start_time_ms = packets[0][1] * 1000.0
#     end_time_ms = packets[-1][1] * 1000.0
#     total_duration_ms = end_time_ms - start_time_ms
#     L_ms = L * 1000.0
#
#     n_segments = int(np.floor(total_duration_ms / L_ms))
#     if n_segments < 1:
#         raise ValueError("Not enough data for even one superperiod.")
#
#     print(f"\nTotal duration: {total_duration_ms/1000:.2f}s | "
#           f"Superperiod (L): {L_ms/1000:.2f}s | Segments: {n_segments}")
#
#     print("\nSegment-wise zone counts:")
#     print("-" * 60)
#
#     for i in range(n_segments):
#         seg_start = start_time_ms + i * L_ms
#         seg_end = seg_start + L_ms
#
#         # Find zones overlapping with this superperiod segment
#         zones_in_seg = [z for z in zones if z[1] > seg_start and z[0] < seg_end]
#         zone_count = len(zones_in_seg)
#
#         print(f"Segment {i:02d}: {seg_start/1000:.2f}–{seg_end/1000:.2f}s | "
#               f"Zones overlapping: {zone_count}")
#
#     print("-" * 60)
#
# def detect_superperiod_differences_with_zones(packets, zones, L, src_ip):
#     """
#     Compare consecutive superperiods based on:
#       1. Number of 84-sized packets sent by src_ip
#       2. Number of zones within each superperiod
#       3. Total duration of zones within each superperiod (in ms)
#     """
#
#     if not packets:
#         raise ValueError("Packets list is empty.")
#     if not zones:
#         raise ValueError("Zones list is empty.")
#
#     # --- Convert everything to milliseconds for consistent comparison ---
#     packets = sorted(packets, key=lambda x: x[1])
#     zones = sorted(zones, key=lambda z: z[0])  # zones already in ms
#
#     start_time_ms = packets[0][1] * 1000.0
#     end_time_ms   = packets[-1][1] * 1000.0
#     total_duration_ms = end_time_ms - start_time_ms
#     L_ms = L * 1000.0
#
#     n_segments = int(np.floor(total_duration_ms / L_ms))
#     if n_segments < 2:
#         raise ValueError("Not enough data for multiple superperiods.")
#
#     diffs = []
#     for i in range(1, n_segments):
#         seg_start_prev = start_time_ms + (i - 1) * L_ms
#         seg_end_prev   = seg_start_prev + L_ms
#         seg_start_curr = start_time_ms + i * L_ms
#         seg_end_curr   = seg_start_curr + L_ms
#
#         # --- 1. 84-packet counts (convert timestamp to ms for comparison) ---
#         count_84_prev = sum(1 for p in packets
#                             if seg_start_prev <= p[1]*1000 < seg_end_prev
#                             and p[2] == src_ip and abs(p[0]) == 84)
#         count_84_curr = sum(1 for p in packets
#                             if seg_start_curr <= p[1]*1000 < seg_end_curr
#                             and p[2] == src_ip and abs(p[0]) == 84)
#         count_diff = abs(count_84_curr - count_84_prev)
#
#         # --- 2. Zones overlapping each superperiod (in ms) ---
#         zones_prev = [z for z in zones if z[1] > seg_start_prev and z[0] < seg_end_prev]
#         zones_curr = [z for z in zones if z[1] > seg_start_curr and z[0] < seg_end_curr]
#
#         zone_count_prev = len(zones_prev)
#         zone_count_curr = len(zones_curr)
#         zone_count_diff = abs(zone_count_curr - zone_count_prev)
#
#         # --- 3. Total duration of zones (in ms) ---
#         def overlap_duration(zones_subset, seg_start, seg_end):
#             dur = 0
#             for z in zones_subset:
#                 overlap_start = max(z[0], seg_start)
#                 overlap_end   = min(z[1], seg_end)
#                 if overlap_end > overlap_start:
#                     dur += (overlap_end - overlap_start)
#             return dur
#
#         zone_duration_prev = overlap_duration(zones_prev, seg_start_prev, seg_end_prev)
#         zone_duration_curr = overlap_duration(zones_curr, seg_start_curr, seg_end_curr)
#         zone_duration_diff = abs(zone_duration_curr - zone_duration_prev)
#
#         diffs.append({
#             "segment_index": i,
#             "start_time_ms": seg_start_curr,
#             "end_time_ms": seg_end_curr,
#             "count_84_prev": count_84_prev,
#             "count_84_curr": count_84_curr,
#             "count_diff": count_diff,
#             "zones_prev": zone_count_prev,
#             "zones_curr": zone_count_curr,
#             "zone_count_diff": zone_count_diff,
#             "zone_duration_prev_ms": zone_duration_prev,
#             "zone_duration_curr_ms": zone_duration_curr,
#             "zone_duration_diff_ms": zone_duration_diff
#         })
#
#     # Identify max diffs
#     max_packet_diff = max(diffs, key=lambda d: d["count_diff"])
#     max_zone_count_diff = max(diffs, key=lambda d: d["zone_count_diff"])
#     max_zone_duration_diff = max(diffs, key=lambda d: d["zone_duration_diff_ms"])
#
#     return {
#         "all_differences": diffs,
#         "max_packet_diff": max_packet_diff,
#         "max_zone_count_diff": max_zone_count_diff,
#         "max_zone_duration_diff": max_zone_duration_diff
#     }














import numpy as np

def detect_superperiod_differences(packets, L, ignore_sizes={84, 76}):
    """
    Compare consecutive superperiod segments in a packet trace and identify
    where traffic patterns change the most.

    Parameters
    ----------
    packets : list of tuples
        Each tuple should be (size, timestamp, src_ip, dst_ip, protocol, ...).
        Only the first two elements are required.
    L : float
        Superperiod duration in seconds.
    ignore_sizes : set, optional
        Packet sizes to ignore when comparing segments (default: {84, 76}).

    Returns
    -------
    dict
        {
            "all_differences": [    # list of diffs for every consecutive pair
                {"segment_index": int,
                 "start_time": float,
                 "end_time": float,
                 "num_packets_diff": int,
                 "size_set_diff": int,
                 "combined_diff": int},
                ...
            ],
            "max_num_packets_diff": {...},   # largest change in packet count
            "max_size_set_diff": {...},      # largest change in size set
            "max_combined_diff": {...}       # largest overall change
        }
    """

    if not packets:
        raise ValueError("Packets list is empty.")

    # Ensure packets are in time order
    packets = sorted(packets, key=lambda x: x[1])
    start_time = int(packets[0][1])
    end_time = int(packets[-1][1])
    total_duration = end_time - start_time

    n_segments = int(np.floor(total_duration / L))
    if n_segments < 2:
        raise ValueError("Not enough data for multiple superperiods.")

    # Split packets into segments of L duration
    segments = []
    for i in range(n_segments):
        seg_start = start_time + i * L
        seg_end = seg_start + L
        seg_pkts = [p for p in packets if seg_start <= p[1] < seg_end]
        segments.append((seg_start, seg_end, seg_pkts))

    # Compare consecutive segments
    diffs = []
    for i in range(1, len(segments)):
        prev_start, prev_end, prev_pkts = segments[i - 1]
        curr_start, curr_end, curr_pkts = segments[i]

        # Filter out ignored packet sizes
        prev_sizes = [p[0] for p in prev_pkts if abs(p[0]) not in ignore_sizes]
        curr_sizes = [p[0] for p in curr_pkts if abs(p[0]) not in ignore_sizes]

        # Metric 1: Difference in number of relevant packets
        num_diff = abs(len(curr_sizes) - len(prev_sizes))

        # Metric 2: Difference in size sets (order-insensitive)
        set_prev = set(prev_sizes)
        set_curr = set(curr_sizes)
        set_diff = len(set_prev.symmetric_difference(set_curr))

        # Metric 3: Combined difference
        combined_diff = num_diff + set_diff

        diffs.append({
            "segment_index": i,
            "start_time": curr_start,
            "end_time": curr_end,
            "num_packets_diff": num_diff,
            "size_set_diff": set_diff,
            "combined_diff": combined_diff
        })

    # Identify max-diff segments
    max_num_packets = max(diffs, key=lambda d: d["num_packets_diff"])
    max_size_set = max(diffs, key=lambda d: d["size_set_diff"])
    max_combined = max(diffs, key=lambda d: d["combined_diff"])

    return {
        "all_differences": diffs,
        "max_num_packets_diff": max_num_packets,
        "max_size_set_diff": max_size_set,
        "max_combined_diff": max_combined
    }


# import numpy as np
#
# def detect_superperiod_differences_by_84(packets, L, src_ip):
#     """
#     Compare consecutive superperiod segments based on the number of 84-sized packets
#     sent by a specific source IP address.
#
#     Parameters
#     ----------
#     packets : list of tuples
#         Each tuple should be (size, timestamp, ipsrc, ipdst, protocol, ack_rtt, ack_frame).
#     L : float
#         Superperiod duration in seconds.
#     src_ip : str
#         The IP address of interest (packets originating from this IP are counted).
#
#     Returns
#     -------
#     dict
#         {
#             "all_differences": [
#                 {
#                     "segment_index": int,
#                     "start_time": float,
#                     "end_time": float,
#                     "count_84_prev": int,
#                     "count_84_curr": int,
#                     "count_diff": int
#                 },
#                 ...
#             ],
#             "max_diff_segment": {
#                 "segment_index": int,
#                 "start_time": float,
#                 "end_time": float,
#                 "count_diff": int
#             }
#         }
#     """
#
#     if not packets:
#         raise ValueError("Packets list is empty.")
#
#     # Sort packets chronologically by timestamp
#     packets = sorted(packets, key=lambda x: x[1])
#     start_time = packets[0][1]
#     end_time = packets[-1][1]
#     total_duration = end_time - start_time
#
#     # Compute number of full superperiods
#     n_segments = int(np.floor(total_duration / L))
#     if n_segments < 2:
#         raise ValueError("Not enough data for multiple superperiods.")
#
#     # Split packets into L-duration superperiod segments
#     segments = []
#     for i in range(n_segments):
#         seg_start = start_time + i * L
#         seg_end = seg_start + L
#         seg_pkts = [p for p in packets if seg_start <= p[1] < seg_end]
#         segments.append((seg_start, seg_end, seg_pkts))
#
#     # Compute differences between consecutive segments
#     diffs = []
#     for i in range(1, len(segments)):
#         prev_start, prev_end, prev_pkts = segments[i - 1]
#         curr_start, curr_end, curr_pkts = segments[i]
#
#         # Count 84-byte packets sent by the target IP in each segment
#         count_84_prev = sum(1 for p in prev_pkts if p[2] == src_ip and abs(p[0]) == 84)
#         count_84_curr = sum(1 for p in curr_pkts if p[2] == src_ip and abs(p[0]) == 84)
#
#         # Compute absolute difference in counts
#         count_diff = abs(count_84_curr - count_84_prev)
#
#         diffs.append({
#             "segment_index": i,
#             "start_time": curr_start,
#             "end_time": curr_end,
#             "count_84_prev": count_84_prev,
#             "count_84_curr": count_84_curr,
#             "count_diff": count_diff
#         })
#
#     # Find segment with the largest change
#     max_diff_segment = max(diffs, key=lambda d: d["count_diff"])
#
#     return {
#         "all_differences": diffs,
#         "max_diff_segment": max_diff_segment
#     }
