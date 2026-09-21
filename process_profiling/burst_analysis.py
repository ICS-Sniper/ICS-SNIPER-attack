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

# def find_stable_zones(t_iat, dt_ms, win=2, mad_thresh=None):
#     log_iat = np.log10(1 + dt_ms)
#     n = len(log_iat)
#
#     # Rolling MAD (Median Absolute Deviation)
#     mad = np.full(n, np.nan)
#     for i in range(n):
#         lo = max(0, i - win//2)
#         hi = min(n, lo + win)
#         lo = hi - win
#         segment = log_iat[lo:hi]
#         med = np.median(segment)
#         mad[i] = np.median(np.abs(segment - med))
#
#     # Automatically select threshold if not provided:
#     # stable = lowest 20% MAD values
#     if mad_thresh is None:
#         mad_thresh = np.quantile(mad[~np.isnan(mad)], 0.2)
#
#     # Also require IAT to be above its median (not tightly spaced)
#     iat_thresh = np.median(dt_ms)
#
#     stable_mask = (mad <= mad_thresh) & (dt_ms >= iat_thresh)
#
#     # Extract continuous stable segments
#     zones = []
#     i = 0
#     while i < n:
#         if stable_mask[i]:
#             j = i
#             while j+1 < n and stable_mask[j+1]:
#                 j += 1
#             zones.append((t_iat[i], t_iat[j], j-i+1))
#             i = j + 1
#         else:
#             i += 1
#
#     return log_iat, mad, stable_mask, zones
#
# # def plot_stable_regions(t_iat, log_iat, stable_mask, zones, save_as=None):
# #     plt.figure(figsize=(12,5))
# #
# #     # Base scatter
# #     plt.scatter(t_iat, log_iat, s=10, color='gray', label="log(IAT)")
# #
# #     # Highlight stable zones
# #     plt.scatter(t_iat[stable_mask], log_iat[stable_mask], s=14, color='blue', label="Stable zone points")
# #
# #     # Shaded time blocks
# #     for (s, e, _) in zones:
# #         plt.axvspan(s, e, color='blue', alpha=0.15)
# #
# #     plt.xlabel("Time (s)")
# #     plt.ylabel("log10(1 + IAT(ms))")
# #     plt.title("Stable Regions (least tightly spaced, lowest variance)")
# #     plt.grid(True)
# #     plt.legend()
# #
# #     if save_as:
# #         plt.tight_layout()
# #         plt.savefig(save_as, dpi=150)
# #         print(f"[SAVED] {save_as}")
# #
# #     plt.show()
#
#
# # # ===================================================
# # # 1) Configure Parameters
# # # ===================================================
# # TARGET_IP = "128.189.240.15"        # <-- Set this to the source IP of interest
# # ROLL_WINDOW = 401            # Size of rolling window (odd number recommended)
# # Z_THRESH = 4.0               # Robust change detection sensitivity
# # SAVE_PREFIX = "burst_analysis"   # Prefix for output files
# #
# # # ===================================================
# # # 2) Extract IAT (Inter-arrival times) for size=84 from given IP
# # # ===================================================
# def extract_iats_ms(packets, flag):
#     # print(packets)
#     if flag==0:
#         rows = [(size, ts) for (size, ts, sip, proto, _, _) in packets if size == 84] # Note: for ENIP
#     # print(rows)
#     if flag==1:
#         rows = [(size, ts) for (size, ts, sip, proto, _, _) in packets] # Note: for Modbus
#     rows.sort(key=lambda x: x[1])
#     if len(rows) < 2:
#         return np.array([]), np.array([])
#     ts = np.array([ts for _, ts in rows], dtype=float)
#     # ts = ts[4:]
#     dt = np.diff(ts) * 1000.0  # convert sec → ms
#     t_iat = ts[1:]             # timestamp aligned to each IAT
#     # print(len(t_iat))
#     # plt.figure(figsize=(14, 5))
#     # plt.plot(t_iat, dt, alpha=0.6, color='steelblue', linewidth=1)
#     #
#     # plt.xlabel("Time (seconds)", fontsize=12)
#     # plt.ylabel("Packet Length (bytes)", fontsize=12)
#     # plt.title("Packet Timeline", fontsize=14)
#     # plt.tight_layout()
#     # # plt.savefig("packet_timeline.png", dpi=150)
#     # plt.show()
#
#     # iatvalues=(sorted(zip(t_iat, dt), key=lambda x: x[0], reverse=False))
#     # for elem in iatvalues:
#     #     print(elem)
#     # for ctr in range(0,len(dt)):
#     #     print(t_iat[ctr], dt[ctr])
#     return t_iat, dt
#
#
# def cluster_zones_by_duration(zones, min_points=2):
#     """
#     zones: list of (start_time_sec, end_time_sec, num_packets)
#     Returns:
#         filtered_zones - zones used for clustering
#         rates          - packets per ms for each zone
#         labels         - cluster labels for each zone
#         clusters       - dict cluster_id -> list of zone indices (relative to filtered_zones)
#     """
#
#     # --- Filter trivial / invalid zones ---
#     filtered_zones = [(s, e, c) for (s, e, c) in zones if c >= min_points and (e > s)]
#     # print(filtered_zones)
#     if len(filtered_zones) < 2:
#         raise ValueError("Not enough valid zones to cluster (need >=2).")
#
#     # --- Compute rates ---
#     durations_ms = np.array([(e - s) for (s, e, c) in filtered_zones], dtype=float)
#     counts       = np.array([c for (_, _, c) in filtered_zones], dtype=float)
#     # rates        = counts / durations_ms
#     # rates = durations_ms
#
#     # --- Hierarchical clustering on rates ---
#     X = durations_ms.reshape(-1, 1)
#     Z = linkage(X, method='ward')
#
#     distances = Z[:, 2]
#     # # prefer relative gap (ratio) selection to avoid bias toward top split
#     # if distances.size < 2:
#     #     cutoff = float(distances[0]) if distances.size == 1 else 0.0
#     # else:
#     #     eps = 1e-12
#     #     ratio = (distances[1:] + eps) / (distances[:-1] + eps)
#     #     floor = np.quantile(distances[distances > 0], 0.05) if np.any(distances > 0) else 0.0
#     #     ratio = np.where(distances[:-1] >= floor, ratio, -np.inf)
#     #     jump_idx = int(np.argmax(ratio))
#     #     cutoff = float((distances[jump_idx] + distances[jump_idx + 1]) / 2.0)
#     jump_idx = np.argmax(np.diff(distances)) if len(distances) > 1 else 0
#     cutoff = distances[jump_idx]
#
#     labels = fcluster(Z, cutoff, criterion="distance")
#
#     # --- Build cluster mapping ---
#     clusters = {}
#     for i, label in enumerate(labels):
#         clusters.setdefault(label, []).append(i)
#
#     return filtered_zones, durations_ms, labels, clusters
#
# # def print_clusters(filtered_zones, rates, clusters):
# #     print("\nCluster results:\n")
# #
# #     for cluster_id, zone_indices in clusters.items():
# #         print(f"Cluster {cluster_id}:")
# #         for idx in zone_indices:
# #             start, end, count = filtered_zones[idx]
# #             rate = rates[idx]
# #             print(f"  start={start:.3f}s   end={end:.3f}s   rate={count/(end-start):.6f} packets/ms")
# #         print()
#
# def select_cluster_with_longest_durations(filtered_zones, clusters):
#     """
#     From the clustered stable zones, select the cluster whose zones have
#     the largest median duration (or mean duration — both similar here).
#
#     Returns:
#         best_cluster_id : int
#         best_zone_indices : list of indices into filtered_zones
#     """
#
#     # Compute durations for each zone
#     durations = np.array([(end - start) for (start, end, count) in filtered_zones], dtype=float)
#
#     best_cluster_id = None
#     best_score = -1
#
#     for cluster_id, zone_indices in clusters.items():
#         cluster_durations = durations[zone_indices]
#
#         # Use median for robustness (mean also fine)
#         cluster_duration_score = np.median(cluster_durations)
#
#         if cluster_duration_score > best_score:
#             best_score = cluster_duration_score
#             best_cluster_id = cluster_id
#
#     best_zone_indices = clusters[best_cluster_id]
#     return best_cluster_id, best_zone_indices
#
# def print_best_cluster(filtered_zones, durations, best_cluster_id, best_zone_indices):
#     print(f"\nSelected Cluster {best_cluster_id} (longest stable durations):\n")
#     for idx in best_zone_indices:
#         start, end, count = filtered_zones[idx]
#         duration = durations[idx]
#         duration = end - start
#         rate = count/duration
#         # print(f"  start={start:.3f}s   end={end:.3f}s   duration={duration:.3f}s   rate={rate:.6f} packets/ms")
#
#
# def circular_concentration_score(t, P):
#     # t: np.array of times (ms), P: trial period (ms)
#     phases = (t % P) / P * 2*np.pi
#     C, S = np.cos(phases).sum(), np.sin(phases).sum()
#     R = np.hypot(C, S) / len(t)  # 0..1 (higher = better alignment)
#     return R
#
# def dominant_period_fold_check(start_times_ms,P_min_ms=None, P_max_ms=None, n_grid=5): # default n_grid=200 / 197 /100 /50
#     t = np.asarray(start_times_ms, dtype=float)
#     t = np.unique(t); t.sort()
#     if len(t) < 3:
#         raise ValueError("Need at least 3 start times.")
#
#     # crude bounds from ISIs
#     isi = np.diff(t)
#     # print (t)
#     # print (isi)
#     lo = np.percentile(isi, 10) if len(isi) > 5 else isi.mean()  # Changed from np.percentile(isi, 10)
#     hi = np.percentile(isi, 90) if len(isi) > 5 else isi.mean()*3 # Changed from np.percentile(isi, 90)
#     P_min_ms = P_min_ms or max(5.0, lo/2)
#     P_max_ms = P_max_ms or max(P_min_ms*2, hi*2)
#
#     Ps = np.linspace(P_min_ms, P_max_ms, n_grid)
#     scores = np.array([circular_concentration_score(t, P) for P in Ps])
#     # for idx in range(0, len(Ps)):
#     #     print(Ps[idx], scores[idx])
#     # print(scores)
#     # print(Ps)
#     # print(circular_concentration_score(t, 30))
#     idx = int(np.argmax(scores))
#     return {"period_ms": int(round(Ps[idx])), "score": float(scores[idx]), "grid_periods": Ps, "grid_scores": scores}
#
#
# def cluster_values(data: list[tuple]) -> list[tuple]:
#     """
#     Performs hierarchical clustering on the values, automatically determining
#     the number of clusters by cutting at the largest gap in merge distances.
#
#     Parameters
#     ----------
#     data : list of (timestamp, value) tuples.
#
#     Returns
#     -------
#     List of (timestamp, cluster_number) tuples.
#     """
#     values = np.array([t[1] for t in data]).reshape(-1, 1)
#
#     linkage_matrix = linkage(values, method='ward')
#
#     # Merge distances at each step of the hierarchy
#     merge_distances = linkage_matrix[:, 2]
#
#     # Find the largest gap between consecutive merge distances
#     gaps       = np.diff(merge_distances)
#     cut_index  = np.argmax(gaps)
#     threshold  = (merge_distances[cut_index] + merge_distances[cut_index + 1]) / 2
#
#     cluster_labels = fcluster(linkage_matrix, t=threshold, criterion='distance')
#
#     return [(ts, int(label)) for (ts, _), label in zip(data, cluster_labels)]
#
# def print_period_rankings(label, n_grid_list, periods, scores):
#     """Result analysis for an n_grid sweep: list candidate periods
#        (a) in decreasing order of score, (b) in decreasing order of frequency."""
#     rows = [(round(float(p), 2), float(s), ng)
#             for p, s, ng in zip(periods, scores, n_grid_list)
#             if not np.isnan(s)]
#     if not rows:
#         print(f"\n[{label}] no valid results to analyze.")
#         return
#
#     # --- (a) by score, decreasing ---
#     print(f"\n[{label}] periods by SCORE (decreasing):")
#     print(f"  {'period':>12}  {'score':>8}  {'n_grid':>7}")
#     for p, s, ng in sorted(rows, key=lambda r: r[1], reverse=True):
#         print(f"  {p:>12.2f}  {s:>8.4f}  {ng:>7d}")
#
#     # --- (b) by frequency of occurrence, decreasing ---
#     freq = defaultdict(list)          # period -> list of scores
#     for p, s, _ng in rows:
#         freq[p].append(s)
#
#     print(f"\n[{label}] periods by FREQUENCY (decreasing):")
#     print(f"  {'period':>12}  {'count':>6}  {'best score':>10}  {'mean score':>10}")
#     for p, ss in sorted(freq.items(), key=lambda kv: (len(kv[1]), max(kv[1])), reverse=True):
#         print(f"  {p:>12.2f}  {len(ss):>6d}  {max(ss):>10.4f}  {np.mean(ss):>10.4f}")
#
# def _cluster_ranges(values, labels):
#     """label -> {lo, hi, center, count}, built from the ORIGINAL values."""
#     buckets = {}
#     for v, lab in zip(values, labels):
#         buckets.setdefault(lab, []).append(v)
#     out = {}
#     for lab, vs in buckets.items():
#         a = np.asarray(vs, dtype=float)
#         out[lab] = {"lo": float(a.min()), "hi": float(a.max()),
#                     "center": float(np.median(a)), "count": int(a.size)}
#     return out
#
# def resolve_period(label, n_grid_list, periods, scores,
#                    strategy="max_rel_gap", max_clusters=None,
#                    transform=lambda v: np.log10(1.0 + v),
#                    k_max=24, pad_rel=0.0, verbose=True):
#     """Order candidate periods by score and by frequency, cluster the values by
#        relative distance, then resolve the final period."""
#     rows = [(int(ng), round(float(p), 2), float(s))
#             for ng, p, s in zip(n_grid_list, periods, scores)
#             if not np.isnan(s) and float(p) > 0]
#     if not rows:
#         print(f"\n[{label}] no valid results.")
#         return None
#
#     values = [p for _, p, _ in rows]
#
#     # --- cluster the period values (relative distance via the log transform) ---
#     labeled = cvs.cluster_values_rel([(ng, p) for ng, p, _ in rows],
#                                  strategy=strategy,
#                                  max_clusters=max_clusters,
#                                  transform=transform)
#     labels = [int(lab) for _, lab in labeled]   # input order; 1-based, ascends with value
#     clusters = _cluster_ranges(values, labels)
#
#     # --- (a) decreasing score ---
#     order_s = sorted(range(len(rows)), key=lambda i: rows[i][2], reverse=True)
#     if verbose:
#         print(f"\n[{label}] periods by SCORE (decreasing):")
#         print(f"  {'period':>10}  {'score':>8}  {'n_grid':>7}  {'cluster':>8}")
#         for i in order_s:
#             ng, p, s = rows[i]
#             print(f"  {p:>10.2f}  {s:>8.4f}  {ng:>7d}  {labels[i]:>8d}")
#
#     # --- (b) decreasing frequency ---
#     freq = Counter(values)
#     best_by_period = {}
#     for i, (_, p, s) in enumerate(rows):
#         if p not in best_by_period or s > best_by_period[p][0]:
#             best_by_period[p] = (s, labels[i])
#     order_f = sorted(freq.items(),
#                      key=lambda kv: (kv[1], best_by_period[kv[0]][0]), reverse=True)
#     if verbose:
#         print(f"\n[{label}] periods by FREQUENCY (decreasing):")
#         print(f"  {'period':>10}  {'count':>6}  {'best score':>10}  {'cluster':>8}")
#         for p, c in order_f:
#             s, lab = best_by_period[p]
#             print(f"  {p:>10.2f}  {c:>6d}  {s:>10.4f}  {lab:>8d}")
#
#     # --- decision ---
#     i_top = order_s[0]
#     P_score, S_score, C_score = rows[i_top][1], rows[i_top][2], labels[i_top]
#     P_freq, N_freq = order_f[0]
#     C_freq = best_by_period[P_freq][1]
#
#     if P_score == P_freq:
#         final = P_score
#         how = "highest-score period == highest-frequency period"
#     else:
#         cl = clusters[C_freq]
#         lo, hi = cl["lo"] * (1.0 - pad_rel), cl["hi"] * (1.0 + pad_rel)
#         cands = [(k, k * P_score) for k in range(2, k_max + 1) if lo <= k * P_score <= hi]
#         if cands:
#             # closest multiple to the cluster centre; swap for min(cands) to take smallest k
#             k, m = min(cands, key=lambda km: abs(km[1] - cl["center"]))
#             final = round(m, 2)
#             how = (f"{P_score:g} x {k} = {m:g} lies in cluster {C_freq} "
#                    f"[{cl['lo']:g}, {cl['hi']:g}] of top-frequency period {P_freq:g}")
#         else:
#             final = P_score
#             how = (f"no multiple of {P_score:g} (k<={k_max}) lies in cluster {C_freq} "
#                    f"[{cl['lo']:g}, {cl['hi']:g}] -- keeping highest-score period")
#
#     if verbose:
#         print(f"\n[{label}] highest score     : {P_score:.2f}  (score {S_score:.4f}, cluster {C_score})")
#         print(f"[{label}] highest frequency : {P_freq:.2f}  (count {N_freq}, cluster {C_freq})")
#         print(f"[{label}] FINAL PERIOD      : {final:.2f}   <- {how}")
#
#     return final
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
    # plot_stable_regions(t_iat, log_iat, stable_mask, zones, save_as="stable_zones.png")

    filtered_zones, durations_ms, labels, clusters = cluster_zones_by_duration(zones)
    # print_clusters(filtered_zones, rates, clusters)

    best_cluster_id, best_zone_indices = select_cluster_with_longest_durations(filtered_zones, clusters)

    print_best_cluster(filtered_zones, durations_ms, best_cluster_id, best_zone_indices)

    # n_grid values to try instead of the single default (n_grid=200)
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

    # print("fold check period ≈", round(best_period_s,2), "s (score:", round(best_score_s,3),
          # ", n_grid:", best_n_grid_s, ")")
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

    # print("fold check period ≈", round(best_period_e,2), "s (score:", round(best_score_e,3),
    #       ", n_grid:", best_n_grid_e, ")")
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
    # iat_cluster_list = cluster_values(iatvalues[:20000])
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

    # --- plot n_grid vs score per cluster ---
    # plt.figure(figsize=(10, 6))
    # for iat, info in cluster_results.items():
    #     ngs = info["n_grids"]
    #     scs = np.array(info["scores"], dtype=float)
    #     periods = info.get("periods", [])
    #     plt.plot(ngs, scs, marker="o", label=f"Cluster {iat}")
    #     # annotate each point with the period value
    #     for x, y, p in zip(ngs, scs, periods):
    #         if np.isnan(y):
    #             continue
    #         plt.text(x, y, str(p), fontsize=8, ha="center", va="bottom", rotation=30)
    #
    # plt.xlabel("n_grid (number of trial periods)")
    # plt.ylabel("Score (circular concentration)")
    # plt.title("dominant_period_fold_check: score vs n_grid per IAT cluster")
    # plt.grid(True)
    # plt.legend()
    # plt.tight_layout()
    # # Save plot instead of showing when pcap_path is provided
    # if pcap_path:
    #     base = os.path.splitext(os.path.basename(pcap_path))[0]
    #     out_dir = os.path.dirname(pcap_path) or '.'
    #     out_path = os.path.join(out_dir, f"{base}_dominant_period_vs_ngrid.png")
    #     plt.savefig(out_path, dpi=150)
    #     plt.close()
    #     print(f"[SAVED] {out_path}")
    # else:
    #     plt.show()

    return cluster_results, None

    ################## fold check ends here

    # log_iat, mad, stable_mask, zones = find_stable_zones(t_iat, dt_ms)
    # print("Stable zones (start, end, length):")
    # for z in zones:
    #     print(z)
    #
    # plot_stable_regions(t_iat, log_iat, stable_mask, zones, save_as="stable_zones.png")

    # filtered_zones, durations_ms, labels, clusters = cluster_zones_by_duration(zones)
    # print_clusters(filtered_zones, rates, clusters)

    # best_cluster_id, best_zone_indices = select_cluster_with_longest_durations(filtered_zones, clusters)

    # print_best_cluster(filtered_zones, durations_ms, best_cluster_id, best_zone_indices)

    # start_times_ms = np.sort(np.array([filtered_zones[i][0] for i in best_zone_indices], float))


    # res_fold_s = dominant_period_fold_check(start_times_ms)
    # print("fold check period ≈", round(res_fold_s["period_ms"],2), "s (score:", round(res_fold_s["score"],3), ")")
    #
    # end_times_ms = np.sort(np.array([filtered_zones[i][1] for i in best_zone_indices], float))
    #
    # res_fold_e = dominant_period_fold_check(end_times_ms)
    # print("fold check period ≈", round(res_fold_e["period_ms"],2), "s (score:", round(res_fold_e["score"],3), ")")
    #
    # avg_periodicity = (round(res_fold_s["period_ms"],2) + round(res_fold_e["period_ms"],2))/2
    #
    # return (round(res_fold_s["period_ms"],2), round(res_fold_e["period_ms"],2)), zones

    # title  = "IAT plot vs timeline"
    # plt.figure(figsize=(12, 4))
    # # plt.plot(t_iat, dt_ms, linewidth=1.2)
    # log_iat = np.log10(1 + dt_ms)
    # plt.scatter(t_iat, log_iat, s=10)  # s = dot size
    # plt.plot(t_iat, log_iat, linewidth=1.2)
    # plt.xlabel("Time (s)")
    # plt.ylabel("Inter-arrival Time (ms)")
    # plt.title(title)
    # plt.grid(True)

    # if save_as:
    #     plt.tight_layout()
    #     plt.savefig(save_as, dpi=150)
    #     print(f"[SAVED] Plot saved to: {save_as}")

    # plt.show()

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

    # results = dict(sorted(results.items(), key=lambda x: x[1]["score"], reverse=True))
    # for key, val in results.items():
    #     print(f"Packet size: {key} | Period: {val['period_ms']:.3f} ms | Score: {val['score']:.4f}")

    # Print results ordered by duration, count, best_score (all descending)
    sorted_list = sorted(
        results_list,
        key=lambda e: (e["count"], e["duration"], e["best_score"]),
        reverse=True,
    )

    # for e in sorted_list:
    #     print(
    #         f"Packet size {e['signed_size']:+d}: count={e['count']} first={e['first_ts']:.6f} "
    #         f"last={e['last_ts']:.6f} duration={e['duration']:.6f}s "
    #         f"best score={e['best_score']:.4f} period={e['best_period']}"
    #     )

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

def analyze_packet_segments(
    packets:         list[tuple],
    legitimate_sizes: list[int | float],
    periodicity:     float,
) -> list[tuple]:
    """
    Parameters
    ----------
    packets          : List of tuples whose first element is packet size
                       and second element is packet timestamp (seconds).
    legitimate_sizes : Collection of packet sizes considered legitimate.
                       Used only to locate the first qualifying packet;
                       all subsequent packets (of any size) are included.
    periodicity      : Segment width in seconds.

    Returns
    -------
    List of (seg_num, seg_start, seg_end, Δpacket_count, Δnew_lengths)
    starting from segment 2 (the first segment for which a comparison
    exists).  All segments are included even if they are empty.
    """
    if not packets:
        return []
    if periodicity <= 0:
        raise ValueError(f"periodicity must be > 0, got {periodicity!r}")

    legitimate_set = set(legitimate_sizes)

    # ------------------------------------------------------------------ #
    # Step 1: find the first packet with a legitimate size                #
    # ------------------------------------------------------------------ #
    # print(packets)
    anchor_index = None
    for i, pkt in enumerate(packets):
        if pkt[0] == 72:
        # if pkt[0] in legitimate_set:
            anchor_index = i
            break

    if anchor_index is None:
        return []   # no legitimate packet found → nothing to analyse

    anchor_time = packets[anchor_index][1]

    # ------------------------------------------------------------------ #
    # Step 2: split packets (from anchor onwards) into fixed-width bins   #
    # ------------------------------------------------------------------ #
    # segment k  covers  [anchor + k*periodicity, anchor + (k+1)*periodicity)
    # We discover how many segments we need from the last packet's time.

    tail_packets = packets[anchor_index:]
    if not tail_packets:
        return []

    last_time     = max(pkt[1] for pkt in tail_packets)
    total_span    = last_time - anchor_time
    n_segments    = int(total_span / periodicity) + 1   # at least 1

    # Each segment is a list of packet tuples that fall within its window.
    segments: list[list[tuple]] = [[] for _ in range(n_segments)]

    for pkt in tail_packets:
        offset = pkt[1] - anchor_time
        idx    = int(offset / periodicity)
        # Guard against floating-point edge case at the very last boundary
        if idx >= n_segments:
            idx = n_segments - 1
        segments[idx].append(pkt)

    # ------------------------------------------------------------------ #
    # Step 3: per-segment statistics                                      #
    # ------------------------------------------------------------------ #
    # For each segment record:
    #   - packet count
    #   - set of NEW lengths seen for the first time up to and including
    #     this segment (cumulative novelty)
    #
    # "change in number of new packet lengths" = how many previously-unseen
    # lengths appeared in this segment vs the previous one, i.e.
    # |new_in_seg_k| - |new_in_seg_(k-1)|  where new_in_seg is the set of
    # lengths that appeared for the first time in that segment.

    seen_lengths_before: set = set()   # lengths seen in all prior segments

    seg_stats = []   # (count, new_lengths_set) per segment
    for seg in segments:
        count           = len(seg)
        lengths_here    = {pkt[0] for pkt in seg}
        new_this_seg    = lengths_here - seen_lengths_before
        seen_lengths_before = lengths_here
        seg_stats.append((count, new_this_seg))

    # ------------------------------------------------------------------ #
    # Step 4: build output (from segment 2 onwards)                       #
    # ------------------------------------------------------------------ #
    results = []
    for k in range(1, n_segments):           # k=0 is segment 1; k=1 is segment 2
        seg_num    = k + 1
        seg_start  = round(anchor_time + k * periodicity, 9)
        seg_end    = round(anchor_time + (k + 1) * periodicity, 9)

        prev_count, prev_new = seg_stats[k - 1]
        curr_count, curr_new = seg_stats[k]

        delta_count   = curr_count - prev_count
        delta_new_len = len(curr_new) - len(prev_new)

        results.append((seg_num, seg_start, seg_end, delta_count, delta_new_len))

    header = f"{'Seg':>4}  {'Seg Start':>12}  {'Seg End':>12}  {'ΔPackets':>9}  {'ΔNew Lengths':>13}"
    separator = "-" * len(header)
    print(separator)
    print(header)
    print(separator)
    for seg_num, start, end, dpkts, dnewlen in results:
        print(f"{seg_num:>4}  {start:>12.6f}  {end:>12.6f}  {dpkts:>+9}  {dnewlen:>+13}")
    print(separator)

    # print(results)
