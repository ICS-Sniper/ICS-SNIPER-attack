import argparse
import pyshark
from sklearn.cluster import KMeans
from ltsutils import *
import numpy as np
from traffic_processing import *
import pickle
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import math
from sklearn.cluster import DBSCAN
import math
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


def extract_payload_sizes(pkt):
    """
    Extract size(s) of OpenVPN payload(s) from the packet.
    Args:
        pkt: The packet to extract payloads from.
        ip_address: IP address for direction flagging.
    Returns:
        A list of sizes for all OpenVPN layers found, or [0] if none.
    """
    sizes = []

    for layer in pkt.layers:
        layer_name = layer.layer_name.upper()

        if layer_name == "OPENVPN":
            if hasattr(layer, 'plen'):
                length = layer.plen
                if length is not None:
                    try:
                        sizes.append(int(length))
                    except ValueError:
                        pass  # skip malformed values

        elif layer_name == "TCP" and pkt.highest_layer == "TCP":
            # Only fall back to TCP length if no OPENVPN layer exists at all
            length = layer.len
            if length is not None:
                try:
                    sizes.append(dir_flag * int(length))
                except ValueError:
                    pass  # skip malformed values

    if not sizes:
        return [0]

    return sizes

def find_stable_zones(t_iat, dt_ms, win=2, mad_thresh=None):
    log_iat = np.log10(1 + dt_ms)
    n = len(log_iat)

    # Rolling MAD (Median Absolute Deviation)
    mad = np.full(n, np.nan)
    for i in range(n):
        lo = max(0, i - win//2)
        hi = min(n, lo + win)
        lo = hi - win
        segment = log_iat[lo:hi]
        med = np.median(segment)
        mad[i] = np.median(np.abs(segment - med))

    # Automatically select threshold if not provided:
    # stable = lowest 20% MAD values
    if mad_thresh is None:
        mad_thresh = np.quantile(mad[~np.isnan(mad)], 0.2)

    # Also require IAT to be above its median (not tightly spaced)
    iat_thresh = np.median(dt_ms)

    stable_mask = (mad <= mad_thresh) & (dt_ms >= iat_thresh)

    # Extract continuous stable segments
    zones = []
    i = 0
    while i < n:
        if stable_mask[i]:
            j = i
            while j+1 < n and stable_mask[j+1]:
                j += 1
            zones.append((t_iat[i], t_iat[j], j-i+1))
            i = j + 1
        else:
            i += 1

    return log_iat, mad, stable_mask, zones


def extract_iats_ms(packets, flag):
    # print(packets)
    if flag==0:
        rows = [(size, ts) for (size, ts, sip, proto, _, _) in packets if size == 84] # Note: for ENIP
    # print(rows)
    if flag==1:
        rows = [(size, ts) for (size, ts, sip, proto, _, _) in packets] # Note: for Modbus
    rows.sort(key=lambda x: x[1])
    if len(rows) < 2:
        return np.array([]), np.array([])
    ts = np.array([ts for _, ts in rows], dtype=float)
    # ts = ts[4:]
    dt = np.diff(ts) * 1000.0  # convert sec → ms
    t_iat = ts[1:]             # timestamp aligned to each IAT
    # print(len(t_iat))
    return t_iat, dt


def cluster_zones_by_duration(zones, min_points=2):
    """
    zones: list of (start_time_sec, end_time_sec, num_packets)
    Returns:
        filtered_zones - zones used for clustering
        rates          - packets per ms for each zone
        labels         - cluster labels for each zone
        clusters       - dict cluster_id -> list of zone indices (relative to filtered_zones)
    """

    # --- Filter trivial / invalid zones ---
    filtered_zones = [(s, e, c) for (s, e, c) in zones if c >= min_points and (e > s)]
    # print(filtered_zones)
    if len(filtered_zones) < 2:
        raise ValueError("Not enough valid zones to cluster (need >=2).")

    # --- Compute rates ---
    durations_ms = np.array([(e - s) for (s, e, c) in filtered_zones], dtype=float)
    counts       = np.array([c for (_, _, c) in filtered_zones], dtype=float)
    # rates        = counts / durations_ms
    # rates = durations_ms

    # --- Hierarchical clustering on rates ---
    X = durations_ms.reshape(-1, 1)
    Z = linkage(X, method='ward')

    distances = Z[:, 2]

    jump_idx = np.argmax(np.diff(distances)) if len(distances) > 1 else 0
    cutoff = distances[jump_idx]

    labels = fcluster(Z, cutoff, criterion="distance")

    # --- Build cluster mapping ---
    clusters = {}
    for i, label in enumerate(labels):
        clusters.setdefault(label, []).append(i)

    return filtered_zones, durations_ms, labels, clusters


def select_cluster_with_longest_durations(filtered_zones, clusters):
    """
    From the clustered stable zones, select the cluster whose zones have
    the largest median duration (or mean duration — both similar here).

    Returns:
        best_cluster_id : int
        best_zone_indices : list of indices into filtered_zones
    """

    # Compute durations for each zone
    durations = np.array([(end - start) for (start, end, count) in filtered_zones], dtype=float)

    best_cluster_id = None
    best_score = -1

    for cluster_id, zone_indices in clusters.items():
        cluster_durations = durations[zone_indices]

        # Use median for robustness (mean also fine)
        cluster_duration_score = np.median(cluster_durations)

        if cluster_duration_score > best_score:
            best_score = cluster_duration_score
            best_cluster_id = cluster_id

    best_zone_indices = clusters[best_cluster_id]
    return best_cluster_id, best_zone_indices

def print_best_cluster(filtered_zones, durations, best_cluster_id, best_zone_indices):
    print(f"\nSelected Cluster {best_cluster_id} (longest stable durations):\n")
    for idx in best_zone_indices:
        start, end, count = filtered_zones[idx]
        duration = durations[idx]
        duration = end - start
        rate = count/duration
        # print(f"  start={start:.3f}s   end={end:.3f}s   duration={duration:.3f}s   rate={rate:.6f} packets/ms")


def circular_concentration_score(t, P):
    # t: np.array of times (ms), P: trial period (ms)
    phases = (t % P) / P * 2*np.pi
    C, S = np.cos(phases).sum(), np.sin(phases).sum()
    R = np.hypot(C, S) / len(t)  # 0..1 (higher = better alignment)
    return R

def dominant_period_fold_check(start_times_ms,P_min_ms=None, P_max_ms=None, n_grid=5): # default n_grid=200 / 197 /100 /50
    t = np.asarray(start_times_ms, dtype=float)
    t = np.unique(t); t.sort()
    if len(t) < 3:
        raise ValueError("Need at least 3 start times.")

    # crude bounds from ISIs
    isi = np.diff(t)
    # print (t)
    # print (isi)
    lo = np.percentile(isi, 10) if len(isi) > 5 else isi.mean()  # Changed from np.percentile(isi, 10)
    hi = np.percentile(isi, 90) if len(isi) > 5 else isi.mean()*3 # Changed from np.percentile(isi, 90)
    P_min_ms = P_min_ms or max(5.0, lo/2)
    P_max_ms = P_max_ms or max(P_min_ms*2, hi*2)

    Ps = np.linspace(P_min_ms, P_max_ms, n_grid)
    scores = np.array([circular_concentration_score(t, P) for P in Ps])

    idx = int(np.argmax(scores))
    return {"period_ms": int(round(Ps[idx])), "score": float(scores[idx]), "grid_periods": Ps, "grid_scores": scores}


def cluster_values(data: list[tuple]) -> list[tuple]:
    """
    Performs hierarchical clustering on the values, automatically determining
    the number of clusters by cutting at the largest gap in merge distances.

    Parameters
    ----------
    data : list of (timestamp, value) tuples.

    Returns
    -------
    List of (timestamp, cluster_number) tuples.
    """
    values = np.array([t[1] for t in data]).reshape(-1, 1)

    linkage_matrix = linkage(values, method='ward')

    # Merge distances at each step of the hierarchy
    merge_distances = linkage_matrix[:, 2]

    # Find the largest gap between consecutive merge distances
    gaps       = np.diff(merge_distances)
    cut_index  = np.argmax(gaps)
    threshold  = (merge_distances[cut_index] + merge_distances[cut_index + 1]) / 2

    cluster_labels = fcluster(linkage_matrix, t=threshold, criterion='distance')

    return [(ts, int(label)) for (ts, _), label in zip(data, cluster_labels)]

def print_period_rankings(label, n_grid_list, periods, scores):
    """Result analysis for an n_grid sweep: list candidate periods
       (a) in decreasing order of score, (b) in decreasing order of frequency."""
    rows = [(round(float(p), 2), float(s), ng)
            for p, s, ng in zip(periods, scores, n_grid_list)
            if not np.isnan(s)]
    if not rows:
        print(f"\n[{label}] no valid results to analyze.")
        return

    # --- (a) by score, decreasing ---
    # print(f"\n[{label}] periods by SCORE (decreasing):")
    # print(f"  {'period':>12}  {'score':>8}  {'n_grid':>7}")
    # for p, s, ng in sorted(rows, key=lambda r: r[1], reverse=True):
    #     print(f"  {p:>12.2f}  {s:>8.4f}  {ng:>7d}")

    # --- (b) by frequency of occurrence, decreasing ---
    freq = defaultdict(list)          # period -> list of scores
    for p, s, _ng in rows:
        freq[p].append(s)

    # print(f"\n[{label}] periods by FREQUENCY (decreasing):")
    # print(f"  {'period':>12}  {'count':>6}  {'best score':>10}  {'mean score':>10}")
    # for p, ss in sorted(freq.items(), key=lambda kv: (len(kv[1]), max(kv[1])), reverse=True):
    #     print(f"  {p:>12.2f}  {len(ss):>6d}  {max(ss):>10.4f}  {np.mean(ss):>10.4f}")

def _cluster_ranges(values, labels):
    """label -> {lo, hi, center, count}, built from the ORIGINAL values."""
    buckets = {}
    for v, lab in zip(values, labels):
        buckets.setdefault(lab, []).append(v)
    out = {}
    for lab, vs in buckets.items():
        a = np.asarray(vs, dtype=float)
        out[lab] = {"lo": float(a.min()), "hi": float(a.max()),
                    "center": float(np.median(a)), "count": int(a.size)}
    return out

def resolve_period(label, n_grid_list, periods, scores,
                   strategy="max_rel_gap", max_clusters=None,
                   transform=lambda v: np.log10(1.0 + v),
                   k_max=24, pad_rel=0.0, verbose=True):
    """Order candidate periods by score and by frequency, cluster the values by
       relative distance, then resolve the final period."""
    rows = [(int(ng), round(float(p), 2), float(s))
            for ng, p, s in zip(n_grid_list, periods, scores)
            if not np.isnan(s) and float(p) > 0]
    if not rows:
        print(f"\n[{label}] no valid results.")
        return None

    values = [p for _, p, _ in rows]

    # --- cluster the period values (relative distance via the log transform) ---
    labeled = cvs.cluster_values_rel([(ng, p) for ng, p, _ in rows],
                                 strategy=strategy,
                                 max_clusters=max_clusters,
                                 transform=transform)
    labels = [int(lab) for _, lab in labeled]   # input order; 1-based, ascends with value
    clusters = _cluster_ranges(values, labels)

    # --- (a) decreasing score ---
    order_s = sorted(range(len(rows)), key=lambda i: rows[i][2], reverse=True)
    # if verbose:
    #     print(f"\n[{label}] periods by SCORE (decreasing):")
    #     print(f"  {'period':>10}  {'score':>8}  {'n_grid':>7}  {'cluster':>8}")
    #     for i in order_s:
    #         ng, p, s = rows[i]
    #         print(f"  {p:>10.2f}  {s:>8.4f}  {ng:>7d}  {labels[i]:>8d}")

    # --- (b) decreasing frequency ---
    freq = Counter(values)
    best_by_period = {}
    for i, (_, p, s) in enumerate(rows):
        if p not in best_by_period or s > best_by_period[p][0]:
            best_by_period[p] = (s, labels[i])
    order_f = sorted(freq.items(),
                     key=lambda kv: (kv[1], best_by_period[kv[0]][0]), reverse=True)
    # if verbose:
    #     print(f"\n[{label}] periods by FREQUENCY (decreasing):")
    #     print(f"  {'period':>10}  {'count':>6}  {'best score':>10}  {'cluster':>8}")
    #     for p, c in order_f:
    #         s, lab = best_by_period[p]
    #         print(f"  {p:>10.2f}  {c:>6d}  {s:>10.4f}  {lab:>8d}")

    # --- decision ---
    i_top = order_s[0]
    P_score, S_score, C_score = rows[i_top][1], rows[i_top][2], labels[i_top]
    P_freq, N_freq = order_f[0]
    C_freq = best_by_period[P_freq][1]

    if P_score == P_freq:
        final = P_score
        how = "highest-score period == highest-frequency period"
    else:
        cl = clusters[C_freq]
        lo, hi = cl["lo"] * (1.0 - pad_rel), cl["hi"] * (1.0 + pad_rel)
        cands = [(k, k * P_score) for k in range(2, k_max + 1) if lo <= k * P_score <= hi]
        if cands:
            # closest multiple to the cluster centre; swap for min(cands) to take smallest k
            k, m = min(cands, key=lambda km: abs(km[1] - cl["center"]))
            final = round(m, 2)
            how = (f"{P_score:g} x {k} = {m:g} lies in cluster {C_freq} "
                   f"[{cl['lo']:g}, {cl['hi']:g}] of top-frequency period {P_freq:g}")
        else:
            final = P_score
            how = (f"no multiple of {P_score:g} (k<={k_max}) lies in cluster {C_freq} "
                   f"[{cl['lo']:g}, {cl['hi']:g}] -- keeping highest-score period")

    if verbose:
        print(f"\n[{label}] highest score     : {P_score:.2f}  (score {S_score:.4f}, cluster {C_score})")
        print(f"[{label}] highest frequency : {P_freq:.2f}  (count {N_freq}, cluster {C_freq})")
        print(f"[{label}] FINAL PERIOD      : {final:.2f}   <- {how}")

    return final
