#!/bin/bash
#sleep 13093.84 # attack 2 - (S-EN-BASE: UF-Depletion)
# sleep 33.53 # attack 1 - (S-EN-BASE: Process Delay)
# No sleep needed for H-MD-BASE: Process Delay
sudo python3 nfqueue_drop.py &
PID=$!
START_TIME=$(date +"%Y-%m-%d %H:%M:%S")
echo "[+] Started nfqueue_drop.py (PID: $PID) at $START_TIME — will stop after $DURATION seconds..." >> attack_timing
sudo iptables -I FORWARD -p tcp --dport 1194 -j NFQUEUE --queue-num 1
sudo iptables -I INPUT  -p tcp --dport 1194 -j NFQUEUE --queue-num 1
# sleep 840.32 - S-EN-BASE
sleep 60 # H-MD-BASE
echo "Stopping nfqueue_drop.py..."
sudo kill $PID
sudo iptables -D FORWARD -p tcp --dport 1194 -j NFQUEUE --queue-num 1
sudo iptables -D INPUT  -p tcp --dport 1194 -j NFQUEUE --queue-num 1
END_TIME=$(date +"%Y-%m-%d %H:%M:%S")
echo "[-] Killed nfqueue_drop.py (PID: $PID) at $END_TIME" >> attack_timing
