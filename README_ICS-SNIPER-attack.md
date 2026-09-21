# ICS-Sniper — Attack Implementation

This repository contains the implementation of **ICS-Sniper**. It has two parts:

- **Process profiling** (`process_profiling/`) — analyzes an encrypted VPN
  traffic capture to estimate the **superperiod** *L* and to rank the **critical
  superperiods**.
- **Active attack** — replays a cycle and drops payload packets in the two
  targeted superperiods.

This README covers the two profiling experiments:
- **Experiment E1: Superperiod identification** → **Claim 1** (ICS-Sniper
  identifies the superperiod with 100% accuracy across all eight configurations;
  §VI-A, Table V).
- **Experiment E2: Critical superperiod identification** → **Claim 2**
  (ICS-Sniper ranks the true first critical superperiod first in 71% of cases and
  second otherwise; §VI-A, Table VI).

---

## 1. Prerequisites

- Linux (tested on Ubuntu 22.04).
- Python 3 and `tshark` installed on the machine.
- Python dependencies: `pip install -r requirements.txt`.
- The captured traces (`.pcap` files) from our dataset. Download them from the
  artifact's Google Drive dataset folder and place each one inside the matching
  configuration folder (see §2). The profiling scripts read raw pcaps and require
  `sudo`.

---

## 2. Repository layout

```
.
├── process_profiling/
│   ├── identify_superperiod.py         # superperiod estimation (E1)
│   └── critical_superperiod.py         # critical superperiod ranking (E2)
├── data_and_results/
│   ├── 1_S-MD-BASE/       s-md-base.pcap
│   ├── 2_S-EN-BASE/       s-en-base.pcap
│   ├── 3_S-EN-RNC/        s-en-rnc.pcap
│   ├── 4_S-EN-PCP/        s-en-pcp.pcap
│   ├── 5_H-MD-BASE/       h-md-base.pcap
│   ├── 6_H-MD-LOSS1/      h-md-loss1.pcap
│   ├── 7_H-MD-LOSS2/      h-md-loss2.pcap
│   └── 8_S-EN-PCP-12/     s-en-pcp-12.pcap
├── test_superperiod_identification.sh  # runs E1 on all 8 configurations
├── test_critical_superperiod.sh        # runs E2 on configurations 1–7
├── requirements.txt
└── README.md
```

Place each downloaded `.pcap` in its corresponding `data_and_results/<config>/`
folder before running.

---

## 3. Superperiod identification (E1)

From the repository root:

```bash
bash test_superperiod_identification.sh
```

This runs the profiling module on all eight captures in turn, printing the
configuration number (1–8) to the terminal as it progresses. Each run writes its
estimated superperiod to:

```
./data_and_results/<config>/results_superperiod
```

> **Runtime:** roughly 20 human-minutes of interaction plus about 1 hour of
> total compute for all eight captures.
>
> **Note:** the script **appends** (`>>`) to `results_superperiod`. To avoid
> mixing results across repeated runs, delete the existing `results_superperiod`
> files before re-running.

---

## 4. Running a single configuration

The underlying command for one capture is:

```bash
sudo python3 ./process_profiling/identify_superperiod.py <path-to-pcap> <endpoint-IP>
```

- `<path-to-pcap>` — the capture to analyze,
  e.g. `./data_and_results/2_S-EN-BASE/s-en-base.pcap`.
- `<endpoint-IP>` — the VPN endpoint IP for that capture, used to determine
  packet direction (PLC→SCADA vs SCADA→PLC). Use the value listed in §7; it is
  already filled in per configuration in the test script.

Example (writing the result into the configuration folder):

```bash
sudo python3 ./process_profiling/identify_superperiod.py \
  ./data_and_results/2_S-EN-BASE/s-en-base.pcap 10.0.0.11 \
  >> ./data_and_results/2_S-EN-BASE/results_superperiod
```

---

## 5. Where to check the results

After a run, open the `results_superperiod` file in the corresponding
configuration folder (or read the terminal output) and compare the estimated
superperiod against the expected value in §7.

---

## 6. Interpreting `results_superperiod`

Each configuration's `results_superperiod` file works through the paper's three
metadata features (overlap-region durations, inter-packet timings/IATs, and
packet sizes), each reported for both directions (PLC→router and SCADA→router).
The file does not print a single final value — you derive the superperiod as
follows:

1. Scan all three metadata and pick out the period values that show **both a high
   alignment score and a high frequency/count**. These are the reliable PLC
   periods.
2. Discard the rest: low-score candidates, rare-size candidates with tiny counts,
   and the fast scan cadence (large count but low score).
3. From the reliable periods, drop any that are harmonics (integer multiples) of
   another, then compute the **LCM of the remaining distinct periods**.
4. The resulting LCM is the superperiod, which should match the configuration's
   row in Table V.

**Worked examples (fill in from each output file):**

| # | Configuration | Reliable periods (high score + high frequency) | LCM = Superperiod | Table V |
|---|---|---|---|---|
| 1 | S-MD-BASE   | 60 s, 70 s   | 420 s      | 420 s |
| 2 | S-EN-BASE   | `<periods>`  | `<LCM>` s  | 420 s |
| 3 | S-EN-RNC    | `<periods>`  | `<LCM>` s  | 420 s |
| 4 | S-EN-PCP    | `<periods>`  | `<LCM>` s  | 180 s |
| 5 | H-MD-BASE   | `<periods>`  | `<LCM>` s  | 30 s  |
| 6 | H-MD-LOSS1  | `<periods>`  | `<LCM>` s  | 30 s  |
| 7 | H-MD-LOSS2  | `<periods>`  | `<LCM>` s  | 210 s |
| 8 | S-EN-PCP-12 | `<periods>`  | `<LCM>` s  | 180 s |

> Example (row 1): the file surfaces 60 s (high score and high count in the
> overlap and IAT steps) and 70 s (high score on a recurring packet size); the
> fast 10 s cadence and rare long periods are discarded. 60 and 70 are not
> harmonics, so LCM(60, 70) = 420 s, matching Table V.

---

## 7. Expected results (Claim 1 / Table V)

The estimated superperiod should match the expected value for every
configuration (accuracy = 100%).

| # | Configuration | pcap | Endpoint IP | Expected superperiod |
|---|---|---|---|---|
| 1 | S-MD-BASE   | `s-md-base.pcap`   | `172.31.36.198` | 420 s |
| 2 | S-EN-BASE   | `s-en-base.pcap`   | `10.0.0.11`     | 420 s |
| 3 | S-EN-RNC    | `s-en-rnc.pcap`    | `10.0.0.11`     | 420 s |
| 4 | S-EN-PCP    | `s-en-pcp.pcap`    | `10.0.0.11`     | 180 s |
| 5 | H-MD-BASE   | `h-md-base.pcap`   | `10.0.0.6`      | 30 s  |
| 6 | H-MD-LOSS1  | `h-md-loss1.pcap`  | `10.0.0.6`      | 30 s  |
| 7 | H-MD-LOSS2  | `h-md-loss2.pcap`  | `10.0.0.6`      | 210 s |
| 8 | S-EN-PCP-12 | `s-en-pcp-12.pcap` | `10.0.0.11`     | 180 s |

Configurations 1–7 are the seven setups of Table II; configuration 8 is the
12-PLC scalability setup (§VI-A, supplementary evaluation (ii)).

---

## 8. Troubleshooting

- **Permission or capture-read errors:** run with `sudo` (the scripts read raw
  pcaps).
- **`tshark: command not found`:** install tshark at the system level.
- **A pcap is missing:** confirm you downloaded it from the dataset folder and
  placed it in the matching `data_and_results/<config>/` directory.
- **Stale or duplicated results:** delete the old `results_superperiod` /
  `results_critical` files before re-running, since both scripts append.

---

## 9. Critical superperiod identification (E2)

Once the superperiod is known (from E1), this step splits the trace into
consecutive superperiod-length segments and compares each segment with its
predecessor to flag and rank the **critical superperiods**.

Run all configurations from the repository root:

```bash
bash test_critical_superperiod.sh
```

This runs on configurations 1–7 (S-EN-PCP-12 is not part of E2), printing the
configuration number to the terminal. Each run writes its output to:

```
./data_and_results/<config>/results_critical
```

The command for a single configuration is:

```bash
sudo python3 ./process_profiling/critical_superperiod.py <path-to-pcap> <endpoint-IP> <superperiod>
```

- `<path-to-pcap>` and `<endpoint-IP>` — as in E1 (see §4 and §7).
- `<superperiod>` — the superperiod (in seconds) recovered in E1 for that
  configuration; it is already filled in per configuration in the test script.

> **Note:** the script **appends** (`>>`) to `results_critical`. Delete the
> existing `results_critical` files before re-running to avoid mixing results.

---

## 10. Interpreting `results_critical`

Each line reports one superperiod segment compared to the one before it:

```
Seg N: [start-end]s | num_packets_diff=A | size_set_diff=B | combined_diff=A+B
```

- `num_packets_diff` — change in total payload packet count vs the previous
  segment (heuristic i of Step 4).
- `size_set_diff` — change in the number of unique packet sizes vs the previous
  segment (heuristic ii of Step 4).
- `combined_diff` — the sum of the two, used as the tie-break magnitude.

To read off the critical superperiods:

1. Any segment with a non-zero difference is a candidate critical superperiod.
2. Rank candidates first by **how many heuristics differ** — segments where
   **both** `num_packets_diff` and `size_set_diff` are non-zero outrank those
   where only one is — then by **`combined_diff`** magnitude.
3. The top-ranked segment is ICS-Sniper's first-choice critical superperiod; its
   `[start-end]s` window is when the attack would target.
4. Cross-check against Table VI. The true first critical superperiod is ranked
   first in 71% of cases and second otherwise, so the number of attempts is
   usually 1 and at most 2. Attempts can exceed 1 when the top-ranked segment's
   transitions are purely local and thus non-disruptive (Appendix B).

**Worked example (S-EN-RNC, superperiod 420 s):**

```
Seg 1: [420.00-840.00]s | num_packets_diff=897 | size_set_diff=7 | combined_diff=904
Seg 2: [840.00-1260.00]s | num_packets_diff=40  | size_set_diff=6 | combined_diff=46
...
```

Seg 1 has both heuristics non-zero and by far the largest magnitude
(combined_diff=904), so it is the top-ranked critical superperiod — the
process-initialization window early in the cycle. Most other segments differ on
only one heuristic or by a small amount, so they rank far lower. Per Table VI,
S-EN-RNC required 2 attempts.

---

## 11. Expected results (Claim 2 / Table VI)

The identified critical transitions and the number of attempts should match
Table VI. Fill in the top-ranked critical segment from each `results_critical`
file.

| # | Configuration | Superperiod (s) | Top-ranked critical segment | Attempts (Table VI) |
|---|---|---|---|---|
| 1 | S-MD-BASE  | 420 | `<[start-end]s>`      | 1 |
| 2 | S-EN-BASE  | 420 | `<[start-end]s>`      | 2 |
| 3 | S-EN-RNC   | 420 | `[420.00-840.00]s`   | 2 |
| 4 | S-EN-PCP   | 180 | `<[start-end]s>`      | 1 |
| 5 | H-MD-BASE  | 30  | `<[start-end]s>`      | 1 |
| 6 | H-MD-LOSS1 | 30  | `<[start-end]s>`      | 1 |
| 7 | H-MD-LOSS2 | 210 | `<[start-end]s>`      | 1 |

For all configurations, ICS-Sniper identified the same five critical transitions
(PLC1: 1→2, PLC2: 1→2, PLC3: 1→2, PLC5: 1→3, PLC6: 1→2; see Table VI).

---

## 12. Where this fits in the evaluation

Experiments E1 and E2 (above) are the profiling half of the evaluation. After
confirming the superperiods (E1) and critical superperiods (E2) here, proceed
to attack impact (E3) and detector evasion (E4, in the `SOTA-detectors-NDSS`
repository), as described in the artifact appendix and the top-level dataset
README.

---
