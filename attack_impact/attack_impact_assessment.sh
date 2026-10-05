#!/usr/bin/env bash
# Compare ENIP packet counts between two reference PCAPs and one test PCAP
# for a chosen scenario (S1, S2 or S3), and report the percentage of packets dropped.
#
# Usage: ./attack_impact_assessment.sh S1|S2|S3
#        (if no argument is given, the script prompts for one)

set -euo pipefail

# ---- Get scenario from user input ----
SCENARIO="${1:-}"
if [ -z "$SCENARIO" ]; then
    read -r -p "Enter scenario (S1 / S2 / S3): " SCENARIO
fi

# ---- Display filter ----
FILTER1='enip and ip.src==10.8.0.5 and frame.time_relative<=14400'
FILTER2='modbus and ip.src==10.8.0.3 and frame.time_relative<=7200'

# ---- Hardcoded URLs per scenario ----
# ---- Due to network disturbances during our experiments, for ENIP, we use average of packet counts from
# two reference files. For Modbus, we use only one
case "$SCENARIO" in
    S1)
        REF_URLS=(
          "https://drive.google.com/file/d/1UZMhqCetlil2E8YPpGv3xF47KKamBisE/view?usp=sharing"
          "https://drive.google.com/file/d/11W2RzuwtG1RMSSqG8RC83DfqPRIOJN7w/view?usp=sharing"
        )
        # REF1_URL="https://drive.google.com/file/d/1UZMhqCetlil2E8YPpGv3xF47KKamBisE/view?usp=sharing"
        # REF2_URL="https://drive.google.com/file/d/11W2RzuwtG1RMSSqG8RC83DfqPRIOJN7w/view?usp=sharing"
        TEST_URL="https://drive.google.com/file/d/1Sj4WT-eWbRv0F5cJU6_XDrtc50wEjOGb/view?usp=sharing"
        FILTER="$FILTER1"
        REF_CSV_URL="https://drive.google.com/file/d/1b69FITtJgG8qPJr28SoFuUqF9YIABFLL/view?usp=sharing"
        ATTACK_CSV_URL="https://drive.google.com/file/d/1pN993gC54fOUmfu2hmxaYjqDWq975j-e/view?usp=sharing"
        REF_CSV="$PWD/$SCENARIO/reference.csv"
        ATTACK_CSV="$PWD/$SCENARIO/attack.csv"
        ;;
    S2)
      REF_URLS=(
            "https://drive.google.com/file/d/1UZMhqCetlil2E8YPpGv3xF47KKamBisE/view?usp=sharing"
            "https://drive.google.com/file/d/11W2RzuwtG1RMSSqG8RC83DfqPRIOJN7w/view?usp=sharing"
        )
      # REF1_URL="https://drive.google.com/file/d/1UZMhqCetlil2E8YPpGv3xF47KKamBisE/view?usp=sharing"
      # REF2_URL="https://drive.google.com/file/d/11W2RzuwtG1RMSSqG8RC83DfqPRIOJN7w/view?usp=sharing"
      TEST_URL="https://drive.google.com/file/d/1Qwr2Vi6m20Z2F8pIOgyUL965E0vRU2nr/view?usp=sharing"
      FILTER="$FILTER1"
      REF_CSV_URL="https://drive.google.com/file/d/1uJjH7c_KYz2LKDFL8lx-TyT0XJr9ZkLq/view?usp=sharing"
      ATTACK_CSV_URL="https://drive.google.com/file/d/1z3V8X47wEPbbY9aWM6E_W17gqqwgT64p/view?usp=sharing"
      REF_CSV="$PWD/$SCENARIO/reference.csv"
      ATTACK_CSV="$PWD/$SCENARIO/attack.csv"
        ;;
    S3)
      REF_URLS=(
        "https://drive.google.com/file/d/1eUSa8xCDNTuoPGpnFso5BZ6YOwS--ac9/view?usp=sharing"
        )
      # REF1_URL="https://drive.google.com/file/d/1eUSa8xCDNTuoPGpnFso5BZ6YOwS--ac9/view?usp=sharing"
      # REF2_URL="https://drive.google.com/file/d/1eUSa8xCDNTuoPGpnFso5BZ6YOwS--ac9/view?usp=sharing"
      TEST_URL="https://drive.google.com/file/d/1FRSxZqIUO1JUPMuA-InXGhWJYqRw1G4r/view?usp=sharing"
      FILTER="$FILTER2"
      REF_CSV_URL="https://drive.google.com/file/d/1ylXZcCRhJeneRpjp11_NneBA5vxiKLD7/view?usp=sharing"
      ATTACK_CSV_URL="https://drive.google.com/file/d/1h_6iKnH5kM24ZEbelUt4hD35JqAg19Vy/view?usp=sharing"
      REF_CSV="$PWD/$SCENARIO/reference.csv"
      ATTACK_CSV="$PWD/$SCENARIO/attack.csv"
        ;;
    *)
        echo "Error: invalid input '$SCENARIO'. Expected 'S1', 'S2' or 'S3'." >&2
        echo "Usage: $0 S1/S2/S3" >&2
        exit 1
        ;;
esac

NUM_REFS=${#REF_URLS[@]}
echo "[$SCENARIO] Using filter: $FILTER"
echo "[$SCENARIO] Reference files: $NUM_REFS"

# ---- Dependency check ----
for cmd in curl tshark awk; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: '$cmd' is not installed." >&2; exit 1; }
done

# ---- Create scenario folder (S1 or S2) in the current working directory ----
mkdir -p "$PWD/$SCENARIO"

# ---- Download files into the scenario folder ----
# REF1_PCAP="$PWD/$SCENARIO/reference1.pcap"
# REF2_PCAP="$PWD/$SCENARIO/reference2.pcap"
# TEST_PCAP="$PWD/$SCENARIO/test.pcap"
REF_PCAPS=()
for ((i = 1; i <= NUM_REFS; i++)); do
    REF_PCAPS+=("$PWD/$SCENARIO/reference${i}.pcap")
done
TEST_PCAP="$PWD/$SCENARIO/test.pcap"


# ---- Download helper ----
# Google Drive does not serve large files directly: the plain link returns a
# small HTML "can't virus-scan this file, download anyway?" page, which is what
# was being saved as a .pcap. This helper extracts the Drive file ID, requests
# the file through Drive's confirmed-download endpoint, and if Drive still
# answers with HTML, reads the confirmation form and re-requests with its values.
# Non-Drive URLs are downloaded as-is.
echo -e "\nMeasuring packet drops\n"
download() {
    local url="$1" dest="$2" id="" tmp

    # Pull the file ID out of any common Drive URL shape.
    if [[ "$url" =~ drive\.google\.com|drive\.usercontent\.google\.com|docs\.google\.com ]]; then
        if [[ "$url" =~ /file/d/([A-Za-z0-9_-]+) ]]; then
            id="${BASH_REMATCH[1]}"
        elif [[ "$url" =~ [?\&]id=([A-Za-z0-9_-]+) ]]; then
            id="${BASH_REMATCH[1]}"
        fi
    fi

    if [ -z "$id" ]; then
        curl -fL --retry 3 -o "$dest" "$url"
    else
        # First attempt: confirmed-download endpoint (works for most large files).
        curl -fL --retry 3 -o "$dest" \
            "https://drive.usercontent.google.com/download?id=${id}&export=download&confirm=t"

        # If Drive still returned an HTML page, parse the confirmation form and retry.
        if head -c 512 "$dest" | grep -qi '<html\|<!doctype'; then
            tmp="$(mktemp)"
            mv "$dest" "$tmp"
            local confirm uuid
            confirm=$(grep -o 'name="confirm" value="[^"]*"' "$tmp" | head -1 | sed 's/.*value="//; s/"$//')
            uuid=$(grep -o 'name="uuid" value="[^"]*"'       "$tmp" | head -1 | sed 's/.*value="//; s/"$//')
            rm -f "$tmp"
            curl -fL --retry 3 -o "$dest" \
                "https://drive.usercontent.google.com/download?id=${id}&export=download&confirm=${confirm:-t}${uuid:+&uuid=$uuid}"
        fi
    fi

    # Final sanity check: refuse to continue with an HTML page or an empty file.
    if [ ! -s "$dest" ] || head -c 512 "$dest" | grep -qi '<html\|<!doctype'; then
        echo "Error: $dest is not a PCAP (empty or HTML page returned)." >&2
        echo "       For Google Drive, make sure the file is shared as 'Anyone with the link'." >&2
        exit 5
    fi
    echo "  saved $(du -h "$dest" | cut -f1) to $dest"
}

# ---- Download ----
for ((i = 0; i < NUM_REFS; i++)); do
    echo "[$SCENARIO] Downloading reference PCAP $((i + 1)) of $NUM_REFS..."
    download "${REF_URLS[$i]}" "${REF_PCAPS[$i]}"
done


echo "[$SCENARIO] Downloading test PCAP..."
download "$TEST_URL" "$TEST_PCAP"

# ---- Count packets matching the filter ----
# Progress goes to stderr so it shows on screen but isn't captured into the count.
# tshark errors are NOT hidden, and a failure stops the script with a clear message.
count_packets() {
    local file="$1" label="$2" out
    echo "[$SCENARIO] Counting packets in $label (this can take a while for large files)..." >&2
    if [ ! -s "$file" ]; then
        echo "Error: $file is missing or empty; the download may have failed." >&2
        exit 4
    fi
    if ! out=$(tshark -r "$file" -Y "$FILTER" -T fields -e frame.number); then
        echo "Error: tshark failed to read $file ($label)." >&2
        echo "       Check that the URL points to the raw PCAP file and not an HTML page." >&2
        exit 4
    fi
    printf '%s\n' "$out" | grep -c . || true
}

# Count each reference file; keep the individual counts and their sum.
ref_counts=()
ref_total=0
for ((i = 0; i < NUM_REFS; i++)); do
    c=$(count_packets "${REF_PCAPS[$i]}" "reference PCAP $((i + 1))")
    ref_counts+=("$c")
    ref_total=$((ref_total + c))
done

test_count=$(count_packets "$TEST_PCAP" "test PCAP")

# Reference count = average of the two reference counts
ref_count=$(awk -v total="$ref_total" -v n="$NUM_REFS" 'BEGIN { printf "%.2f", total / n }')

# echo "ref1_count = $ref1_count"
# echo "ref2_count = $ref2_count"
# Print individual reference counts only when there is more than one.
# if [ "$NUM_REFS" -gt 1 ]; then
    # for ((i = 0; i < NUM_REFS; i++)); do
    #     echo "ref$((i + 1))_count = ${ref_counts[$i]}"
    # done
echo "ref_count  = $ref_count (average)"
# else
#     echo "ref_count  = $ref_count"
# fi
echo "test_count = $test_count"

# ---- Handle zero counts ----
if [ "$NUM_REFS" -gt 1 ] && [ "$ref_total" -ne 0 ]; then
    for c in "${ref_counts[@]}"; do
        if [ "$c" -eq 0 ]; then
            echo "Warning: one reference file matched 0 packets; the average may be skewed." >&2
            break
        fi
    done
fi

echo "test_count = $test_count"

# ---- Handle zero counts ----
if [ "$NUM_REFS" -gt 1 ] && [ "$ref_total" -ne 0 ]; then
    for c in "${ref_counts[@]}"; do
        if [ "$c" -eq 0 ]; then
            echo "Warning: one reference file matched 0 packets; the average may be skewed." >&2
            break
        fi
    done
fi

if [ "$ref_total" -eq 0 ] && [ "$test_count" -eq 0 ]; then
    echo "Error: no packets matched the filter in any PCAP." >&2
    echo "       Check the filter and the source IP / time window." >&2
    exit 2
elif [ "$ref_total" -eq 0 ]; then
    echo "Error: reference count is 0 but test count is $test_count; cannot compute drop percentage." >&2
    exit 3
elif [ "$test_count" -eq 0 ]; then
    echo "Warning: test count is 0; all reference packets were dropped." >&2
fi

# ---- Compute drop percentage ----
drop=$(awk -v r="$ref_count" -v t="$test_count" 'BEGIN { printf "%.2f", ((r - t) / r) * 100 }')

echo "Percentage of packets dropped = ${drop}%"

#############################################
# ----- Computing process impact ----#
#############################################
echo -e "\n\n Evaluating attack impact"
echo "[$SCENARIO] Downloading reference CSV..."
download "$REF_CSV_URL" "$REF_CSV"
echo "[$SCENARIO] Downloading attack CSV..."
download "$ATTACK_CSV_URL" "$ATTACK_CSV"

# Seconds -> minutes (2 decimal places)
to_min() { awk -v s="$1" 'BEGIN { printf "%.2f", s / 60 }'; }

if [ "$SCENARIO" = "S1" ] || [ "$SCENARIO" = "S3" ]; then

    # Prints Open - Start in seconds for one CSV (timestamp in column 1, HH:MM:SS at the end).
    pump_start_time() {
        awk -F',' '
        NR == 1 {
            gsub(/\r|"/, "")
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^HMI\.P[1-6]\.State$/) s[i] = 1
                if ($i == "HMI.P501.Status") p = i
            }
            next
        }
        {
            gsub(/\r|"/, "")
            n = split($1, t, /[ :]/)
            now = t[n-2] * 3600 + t[n-1] * 60 + t[n]
            if (NR > 2) {
                if (start == "") for (i in s) if (prev[i] + 0 == 0 && $i + 0 == 1) start = now
                if (open == "" && pp + 0 == 2 && $p + 0 == 1) open = now
            }
            for (i in s) prev[i] = $i
            pp = $p
        }
        END {
            if (p == 0 || start == "" || open == "") exit 1
            d = open - start
            if (d < 0) d += 86400
            print d
        }' "$1" || { echo "Error: could not find Start/Open in $1." >&2; exit 6; }
    }

    ref_pump=$(pump_start_time "$REF_CSV")
    attack_pump=$(pump_start_time "$ATTACK_CSV")

    echo "Time to start clean water pumping (P501 start time) under benign conditions = $(to_min "$ref_pump") min"
    echo "Time to start clean water pumping (P501 start time) under attack = $(to_min "$attack_pump") min"
    echo "Delay caused due to attack  = $(to_min $((attack_pump - ref_pump))) min"
fi


if [ "$SCENARIO" = "S2" ]; then
  p3_state12_time() {
    awk -F',' '
    NR == 1 {
        gsub(/\r|"/, "")
        for (i = 1; i <= NF; i++) if ($i == "HMI.P3.State") p = i
        next
    }
    {
        gsub(/\r|"/, "")
        n = split($1, t, /[ :]/)
        now = t[n-2] * 3600 + t[n-1] * 60 + t[n]
        if (NR > 2 && pp + 0 == 12) { d = now - last; if (d < 0) d += 86400; total += d }
        pp = $p
        last = now
    }
    END {
        if (p == 0) exit 1
        print total + 0
    }' "$1" || { echo "Error: HMI.P3.State column not found in $1." >&2; exit 6; }
  }

  ref_s12=$(p3_state12_time "$REF_CSV")
  attack_s12=$(p3_state12_time "$ATTACK_CSV")

  # echo "Time in stage-3 state 12 (reference) = $(to_min "$ref_s12") min"
  # echo "Time in stage-3 state 12 (attack)    = $(to_min "$attack_s12") min"
  # echo "Difference (attack - reference)      = $(to_min $((attack_s12 - ref_s12))) min"

  # Prints (time HMI.MV304.Status goes 1 -> 2 for the second time) - Start, in seconds, for one CSV.
  # Start = earliest time any of HMI.P1.State..HMI.P6.State goes 0 -> 1
  mv304_second_open_time() {
      awk -F',' '
      NR == 1 {
          gsub(/\r|"/, "")
          for (i = 1; i <= NF; i++) {
              if ($i ~ /^HMI\.P[1-6]\.State$/) s[i] = 1
              if ($i == "HMI.MV304.Status") p = i
          }
          next
      }
      {
          gsub(/\r|"/, "")
          n = split($1, t, /[ :]/)
          now = t[n-2] * 3600 + t[n-1] * 60 + t[n]
          if (NR > 2) {
              if (start == "") for (i in s) if (prev[i] + 0 == 0 && $i + 0 == 1) start = now
              if (pp + 0 == 1 && $p + 0 == 2 && ++count == 2) second = now
          }
          for (i in s) prev[i] = $i
          pp = $p
      }
      END {
          if (p == 0 || start == "" || second == "") exit 1
          d = second - start
          if (d < 0) d += 86400
          print d
      }' "$1" || { echo "Error: could not find Start or the second MV304 1 -> 2 change in $1." >&2; exit 6; }
  }

  ref_mv304=$(mv304_second_open_time "$REF_CSV")
  attack_mv304=$(mv304_second_open_time "$ATTACK_CSV")

  echo "Time to finally close the P3 backwash valve (second MV304 1->2 transition) under benign conditions = $(to_min "$ref_mv304") min"
  echo "Time to finally close the P3 backwash valve (second MV304 1->2 transition) under attack conditions = $(to_min "$attack_mv304") min"
  echo "Difference (attack - reference)        = $(to_min $((attack_mv304 - ref_mv304))) min"
fi
