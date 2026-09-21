#!/bin/bash

echo "1"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/1_S-MD-BASE/s-md-base.pcap 172.31.36.198 420 >> ./data_and_results/1_S-MD-BASE/results_critical
# sleep 60
#
echo "2"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/2_S-EN-BASE/s-en-base.pcap 10.0.0.11 420 >> ./data_and_results/2_S-EN-BASE/results_critical
# sleep 60
#
echo "3"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/3_S-EN-RNC/s-en-rnc.pcap 10.0.0.11 420 >> ./data_and_results/3_S-EN-RNC/results_critical
# sleep 60
#
echo "4"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/4_S-EN-PCP/s-en-pcp.pcap 10.0.0.11 180 >> ./data_and_results/4_S-EN-PCP/results_critical
# sleep 60
#
echo "5"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/5_H-MD-BASE/h-md-base.pcap 10.0.0.6 30 >> ./data_and_results/5_H-MD-BASE/results_critical
# sleep 60
#
echo "6"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/6_H-MD-LOSS1/h-md-loss1.pcap 10.0.0.6 30 >> ./data_and_results/6_H-MD-LOSS1/results_critical
# sleep 60
#
echo "7"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/7_H-MD-LOSS2/h-md-loss2.pcap 10.0.0.6 210 >> ./data_and_results/7_H-MD-LOSS2/results_critical
# sleep 60
#
