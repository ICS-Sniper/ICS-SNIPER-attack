#!/bin/bash

echo "1"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/1_S-MD-BASE/s-md-base.pcap 16.145.224.84 35.160.103.117 420 >> ./data_and_results/1_S-MD-BASE/results_critical
sleep 30

echo "2"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/2_S-EN-BASE/s-en-base.pcap 96.49.203.41 34.215.55.145 420 >> ./data_and_results/2_S-EN-BASE/results_critical
# sleep 30
#
echo "3"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/3_S-EN-RNC/s-en-rnc.pcap 96.49.203.41 34.215.55.145 420 >> ./data_and_results/3_S-EN-RNC/results_critical
# sleep 30
#
echo "4"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/4_S-EN-PCP/s-en-pcp.pcap 96.49.203.41 34.215.55.145 180 >> ./data_and_results/4_S-EN-PCP/results_critical
sleep 30
# #
echo "5"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/5_H-MD-BASE/h-md-base.pcap 128.189.240.15 34.217.194.166 30 >> ./data_and_results/5_H-MD-BASE/results_critical
sleep 30
# #
echo "6"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/6_H-MD-LOSS1/h-md-loss1.pcap 128.189.240.15 44.245.211.234 30 >> ./data_and_results/6_H-MD-LOSS1/results_critical
sleep 30
# #
echo "7"
sudo python3 ./process_profiling/critical_superperiod.py ./data_and_results/7_H-MD-LOSS2/h-md-loss2.pcap 128.189.240.15 44.245.211.234 210 >> ./data_and_results/7_H-MD-LOSS2/results_critical
