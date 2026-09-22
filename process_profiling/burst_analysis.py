import math
import numpy as np
import matplotlib.pyplot as plt
import csv
import os
from collections import defaultdict, Counter
from statistics import median
from scipy.cluster.hierarchy import linkage, fcluster
from scipy.spatial.distance import pdist
from scipy.fft import rfft, rfftfreq
import cluster_values_scalable as cvs
import heapq
from typing import Callable, Iterable, Sequence
from traffic_processing import *


# ===================================================
# Master Functions
# ===================================================
def analyze_stable(packets, pcap_path: str | None = None):
    # TARGET_IP = targetip
    t_iat, dt_ms = extract_iats_ms(packets,0)
    if len(dt_ms) == 0:
        print("Cannot find stable periods")
        return None, None

    log_iat, mad, stable_mask, zones = find_stable_zones(t_iat, dt_ms)
    # print("Stable zones (start, end, length):")
    # for z in zones:
    #     print(z)
    #

    filtered_zones, durations_ms, labels, clusters = cluster_zones_by_duration(zones)

    best_cluster_id, best_zone_indices = select_cluster_with_longest_durations(filtered_zones, clusters)

    print_best_cluster(filtered_zones, durations_ms, best_cluster_id, best_zone_indices)

    n_grid_list = list(range(5, 401, 5))

    start_times_ms = np.sort(np.array([filtered_zones[i][0] for i in best_zone_indices], float))

    scores_s = []
    periods_s = []

    for ng in n_grid_list:
        try:
            res = dominant_period_fold_check(start_times_ms, n_grid=ng)
            scores_s.append(float(res.get("score", 0.0)))
            periods_s.append(int(round(float(res.get("period_ms", 0.0)))))
            # print(float(res.get("score", 0.0)),int(round(float(res.get("period_ms", 0.0)))))
        except ValueError:
            scores_s.append(float('nan'))
            periods_s.append(0.0)

    print_period_rankings("start times", n_grid_list, periods_s, scores_s)
    # best across n_grid
    if any(not np.isnan(s) for s in scores_s):
        valid_idx = [idx for idx, s in enumerate(scores_s) if not np.isnan(s)]
        best_idx = max(valid_idx, key=lambda i: scores_s[i])
        best_score_s = scores_s[best_idx]
        best_period_s = periods_s[best_idx]
        best_n_grid_s = n_grid_list[best_idx]
    else:
        best_score_s = float('nan')
        best_period_s = 0.0
        best_n_grid_s = None

    P_start = resolve_period("start times", n_grid_list, periods_s, scores_s)

    end_times_ms = np.sort(np.array([filtered_zones[i][1] for i in best_zone_indices], float))

    scores_e = []
    periods_e = []

    for ng in n_grid_list:
        try:
            res = dominant_period_fold_check(end_times_ms, n_grid=ng)
            scores_e.append(float(res.get("score", 0.0)))
            periods_e.append(int(round(float(res.get("period_ms", 0.0)))))
        except ValueError:
            scores_e.append(float('nan'))
            periods_e.append(0.0)

    print_period_rankings("end times", n_grid_list, periods_e, scores_e)
    # best across n_grid
    if any(not np.isnan(s) for s in scores_e):
        valid_idx = [idx for idx, s in enumerate(scores_e) if not np.isnan(s)]
        best_idx = max(valid_idx, key=lambda i: scores_e[i])
        best_score_e = scores_e[best_idx]
        best_period_e = periods_e[best_idx]
        best_n_grid_e = n_grid_list[best_idx]
    else:
        best_score_e = float('nan')
        best_period_e = 0.0
        best_n_grid_e = None

    P_end = resolve_period("end times", n_grid_list, periods_e, scores_e)

    avg_periodicity = (round(best_period_s,2) + round(best_period_e,2))/2

    # return (round(best_period_s,2), round(best_period_e,2)), zones
    return (P_start, P_end), zones

def analyze_iat(packets, pcap_path: str | None = None):
    t_iat, dt_ms = extract_iats_ms(packets,1)
    print("Extracted IATs")
    if len(dt_ms) == 0:
        print("No packets from target IP found.")
        return

    iatvalues=(sorted(zip(t_iat, dt_ms), key=lambda x: x[0], reverse=False))

    iat_cluster_list = cvs.cluster_values_rel(iatvalues, strategy="max_rel_gap")
    # print(iat_cluster_list)

    from collections import defaultdict
    iat_buckets = defaultdict(list)
    for ts, clusterval in iat_cluster_list:
        iat_buckets[clusterval].append(ts)
        # print(clusterval, ts)



    # --- 3) Run fold check on each IAT bucket ---
    results = {}
    print(f"\nDominant period by IAT cluster:\n")

    # Sweep n_grid values and record scores for each IAT cluster
    n_grid_list = list(range(1, 301, 5))
    cluster_results = {}

    for iat in sorted(iat_buckets.keys()):
        times = np.array(sorted(iat_buckets[iat]))

        if len(times) < 3:
            print(f"  Value:  too few instances ({len(times)}) — skipped")
            continue

        scores = []
        periods = []

        for ng in n_grid_list:
            try:
                res = dominant_period_fold_check(times, n_grid=ng)
                scores.append(float(res.get("score", 0.0)))
                periods.append(int(res.get("period_ms", 0)))
            except ValueError:
                scores.append(float('nan'))
                periods.append(0)

        # best across n_grid
        if any(not np.isnan(s) for s in scores):
            valid_idx = [idx for idx, s in enumerate(scores) if not np.isnan(s)]
            best_idx = max(valid_idx, key=lambda i: scores[i])
            best_score = scores[best_idx]
            best_period = periods[best_idx]
        else:
            best_score = float('nan')
            best_period = 0

        cluster_results[iat] = {
            "n_grids": n_grid_list,
            "scores": scores,
            "periods": periods,
            "best_score": best_score,
            "best_period": best_period,
        }

        # additional info: number of elements, first/last timestamp and duration
        count = len(times)
        first_ts = float(np.min(times)) if count > 0 else 0.0
        last_ts = float(np.max(times)) if count > 0 else 0.0
        duration = last_ts - first_ts
        print(
            f"IAT Cluster {iat}: count={count} first={first_ts:.6f} last={last_ts:.6f} "
            f"duration={duration:.6f}s best score={best_score:.4f} period={best_period}"
        )

    return cluster_results, None


def analyze_sizes(packets):
    """
    For each unique packet size seen to/from targetip, run a dominant-period
    fold check on the timestamps of that size.

    Packets FROM targetip  → size treated as positive
    Packets TO   targetip  → size treated as negative (opposite direction)

    Steps 2-4 of analyze() are skipped; we go straight to dominant_period_fold_check
    for each signed size bucket.
    """

    # --- 1) Filter and sign packets by direction ---
    relevant = []
    for (size, ts, sip, proto, _, _) in packets:
        relevant.append((size, float(ts)))

    if not relevant:
        print("No packets to/from target IP found.")
        return {}

    # --- 2) Group timestamps by signed size ---
    from collections import defaultdict
    size_buckets = defaultdict(list)
    for signed_size, ts in relevant:
        size_buckets[signed_size].append(ts)

    # --- 3) Run fold check on each size bucket ---
    results = {}
    print(f"\nDominant period by packet size:\n")

    # Sweep n_grid values and record scores for each IAT cluster
    n_grid_list = list(range(1, 301, 5))
    cluster_results = {}

    results_list = []
    for signed_size in sorted(size_buckets.keys()):
        times = np.array(sorted(size_buckets[signed_size]))

        if len(times) < 3:
            # print(f"  size={signed_size:+d}:  too few packets ({len(times)}) — skipped")
            continue

        scores = []
        periods = []

        for ng in n_grid_list:
            try:
                res = dominant_period_fold_check(times, n_grid=ng)
                # results[signed_size] = res
                scores.append(float(res.get("score", 0.0)))
                periods.append(int(res.get("period_ms", 0)))
                # direction = "outbound" if signed_size > 0 else "inbound"
                # print(
                #     f"  size={signed_size:+5d} ({direction}): "
                #     f"period ≈ {res['period_ms']:.2f} s   "
                #     f"score = {res['score']:.3f}   "
                #     f"n = {len(times)}"
                # )
            except ValueError as e:
                scores.append(float('nan'))
                periods.append(0)
                print(f"  size={signed_size:+d}:  skipped — {e}")

        # best across n_grid
        if any(not np.isnan(s) for s in scores):
            valid_idx = [idx for idx, s in enumerate(scores) if not np.isnan(s)]
            best_idx = max(valid_idx, key=lambda i: scores[i])
            best_score = scores[best_idx]
            best_period = periods[best_idx]
        else:
            best_score = float('nan')
            best_period = 0

        cluster_results[signed_size] = {
            "n_grids": n_grid_list,
            "scores": scores,
            "periods": periods,
            "best_score": best_score,
            "best_period": best_period,
        }
        count = len(times)
        first_ts = float(np.min(times)) if count > 0 else 0.0
        last_ts = float(np.max(times)) if count > 0 else 0.0
        duration = last_ts - first_ts

        results_list.append({
            "signed_size": signed_size,
            "count": count,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "duration": duration,
            "best_score": best_score,
            "best_period": best_period,
        })


    # Print results ordered by duration, count, best_score (all descending)
    sorted_list = sorted(
        results_list,
        key=lambda e: (e["count"], e["duration"], e["best_score"]),
        reverse=True,
    )


    # --- Aggregate by period ---
    ## Eliminate packets outside protocol size range, and low frequency
    period_totals = defaultdict(lambda: {"score_sum": 0.0, "count_sum": 0, "sizes": []})
    for e in results_list:
        if np.isnan(e["best_score"]):
            continue
        agg = period_totals[e["best_period"]]
        agg["score_sum"] += e["best_score"]
        agg["count_sum"] += e["count"]
        agg["sizes"].append(e["signed_size"])

    print("\nPeriods by cumulative score:\n")
    for period, agg in sorted(period_totals.items(),
                              key=lambda kv: kv[1]["count_sum"], reverse=True):
        print(
            f"Period {period}: cumulative score={agg['score_sum']:.4f} "
            f"cumulative count={agg['count_sum']} "
            f"sizes={sorted(agg['sizes'])}"
        )

    return cluster_results, None
