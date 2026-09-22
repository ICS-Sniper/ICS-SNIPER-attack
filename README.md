# ICS-Sniper — Attack Implementation

This repository contains the implementation of **ICS-Sniper**. It has two parts:

- **Process profiling** (`process_profiling/`) — analyzes an encrypted VPN traffic capture to estimate the **superperiod** *L* and to rank the **critical superperiods**.
- **Active attack** (`active_attack/`) — replays a cycle and drops payload packets in the two targeted superperiods.

**Prerequisites**

- Linux (tested on Ubuntu 22.04).
- Python 3 installed on the machine.
- Python dependencies: `pip install -r requirements.txt`.
- The captured traces (`.pcap` files) from our dataset. Download them from the
  artifact's Google Drive dataset folder and place each one inside the matching
  configuration folder (see §2). The profiling scripts read raw pcaps and require
  `sudo`.

---

**Repository layout**

```
.
├── process_profiling/
│   └── identify_superperiod.py         # superperiod estimation (E1)
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
├── requirements.txt
└── README.md
```

Place each downloaded `.pcap` in its corresponding `data_and_results/<config>/` folder before running. You can skip the metadata extraction step if you do not delete the zipped .pkl files in each config folder. That will cut down the total execution time. Unzip the .zip files inside each `data_and_results/<config>/` folder before starting the code execution.

---
## Experiment E1: Superperiod identification
It supports **Claim 1** of the paper (ICS-Sniper identifies the superperiod with 100% accuracy across all eight configurations; see §VI-A and Table V).

**1. Quick start (all configurations)**

From the repository root:

```bash
bash test_superperiod_identification.sh
```

This runs the profiling module on all eight captures in turn. Each run writes its
estimated superperiod to:

```
./data_and_results/<config>/results_superperiod
```

---

**2. Running a single configuration**

The underlying command for one capture is:

```bash
sudo python3 ./process_profiling/identify_superperiod.py <path-to-pcap> <compromised-router-IP>
```

- `<path-to-pcap>` — the capture to analyze,
  e.g. `./data_and_results/2_S-EN-BASE/s-en-base.pcap`.
- `<compromised-router-IP>` — the IP address of the compromised router is already filled in per configuration in the test script.

Example (writing the result into the configuration folder):

```bash
sudo python3 ./process_profiling/identify_superperiod.py \
  ./data_and_results/2_S-EN-BASE/s-en-base.pcap 10.0.0.11 \
  >> ./data_and_results/2_S-EN-BASE/results_superperiod
```

---

**3. Where to check the results**

After a run, open the `results_superperiod` file in the corresponding
configuration folder.

---
**4. Interpreting `results_superperiod`**

Each configuration's `results_superperiod` file works through the paper's three
metadata features (overlap-region durations, inter-packet timings/IATs, and
packet sizes), each reported for both directions (PLC→router and SCADA→router).
The file does not print a single final value — you derive the superperiod as
follows:

1. Scan all three metadata and pick out the period values that show **both a high alignment score and a high frequency/count**. These are the reliable PLC periods.
2. Discard the rest: low-score candidates, rare-size candidates with tiny counts, and the fast scan cadence (large count but low score).
3. From the reliable periods, drop any that are factors of another, then compute the **LCM of the remaining distinct periods**.
4. The resulting LCM is the superperiod, which should match the configuration's row in Table V.

**Worked superperiods from each output file:**

| # | Configuration | Reliable periods (high score + high frequency) | LCM = Superperiod | Expected result (Table V) |
|---|---|---|---|---|
| 1 | S-MD-BASE   | 60s, 420s, 70s | 420s      | 420s |
| 2 | S-EN-BASE   | 420s, 30s, 60s, 10s, 70s  | 420s | 420s |
| 3 | S-EN-RNC    | 420s, 10s, 30s, 70s  | 420s | 420s |
| 4 | S-EN-PCP    | 90s, 60s, 180s, 10s, 30s  | 180s  | 180s |
| 5 | H-MD-BASE   | 5s, 6s, 10s  | 30s  | 30s  |
| 6 | H-MD-LOSS1  | 5s, 6s, 10s  | 30s  | 30s  |
| 7 | H-MD-LOSS2  | 7s, 10s, 6s  | 210s  | 210s |
| 8 | S-EN-PCP-12 | 90s, 180s, 45s  | 180s  | 180s |

---

**5. Troubleshooting**

- **Permission or capture-read errors:** run with `sudo` (the scripts read raw
  pcaps).
- **`tshark: command not found`:** install tshark at the system level.
- **A pcap is missing:** confirm you downloaded it from the dataset folder and
  placed it in the matching `data_and_results/<config>/` directory.
- **Stale or duplicated results:** delete the old `results_superperiod` files
  before re-running, since the script appends.

---

**6. Where this fits in the evaluation**

This experiment (E1) is the first of four. After confirming the superperiods and endpoint IP addresses here, proceed to critical-superperiod ranking (E2), attack impact (E3), and
detector evasion (E4, in the `SOTA-detectors-NDSS` repository), as described in
the artifact appendix and the top-level dataset README.


---
## Experiment E2: Critical Superperiod identification

It supports **Claim 2** of the paper (ICS-Sniper correctly identifies the critical superperiods, ranking the true first critical superperiod first in 5 out of 7 cases and second in the remaining ones.
Once the superperiod is known (from E1), this step splits the trace into consecutive superperiod-length segments and compares each segment with its predecessor to flag and rank the **critical superperiods**.

**1. Quick start (all configurations)**

  Run all configurations from the repository root:

  ```bash
  bash test_critical_superperiod.sh
  ```

  This runs on configurations 1–7 (S-EN-PCP-12 is not part of E2). Each run writes its output to:

  ```
  ./data_and_results/<config>/results_critical
  ```

  ---

  **2. Running a single configuration**  

  The command for a single configuration is:

  ```bash
  sudo python3 ./process_profiling/critical_superperiod.py <path-to-pcap> <endpoint-IP> <superperiod>
  ```

  - `<path-to-pcap>` — as in E1.
  - `<superperiod>` and `<endpoint-IP>` — the superperiod (in seconds) and VPN endpoint IP addresses recovered in E1 for that
    configuration; it is already filled in per configuration in the test script.

  > **Note:** the script **appends** (`>>`) to `results_critical`. Delete the
  > existing `results_critical` files before re-running to avoid mixing results.

  ---
  **3. Where to check the results**

  After a run, open the `results_critical` file in the corresponding
  configuration folder.

  ---

**4. Interpreting `results_critical`**

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
