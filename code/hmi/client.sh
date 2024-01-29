#!/bin/bash

usage() {
    echo "Usage: $0 [plc1_comm] [plc2_comm]"
    echo "Where 'plcn_comm' is the communication mode of the nth PLC (tcp' or 'udp')"
    exit 1
}

if [ "$#" -ne 2 ]; then
    usage
    exit 1
fi

PLC1_COMM="$1"
PLC2_COMM="$2"

valid_protocols=("udp" "tcp")
if [[ ! " ${valid_protocols[@]} " =~ " $PLC1_COMM " || ! " ${valid_protocols[@]} " =~ " $PLC2_COMM " ]]; then
    echo "plc1_comm and plc2_comm must be either udp or tcp"
    exit 1
fi

while :; do     
    python3 client.py -c "$PLC1_COMM" --host 172.16.238.120 --port 502 rc --quantity 1 --start 0
    python3 client.py -c "$PLC1_COMM" --host 172.16.238.120 --port 502 rhr --quantity 4 --start 40001
    python3 client.py -c "$PLC2_COMM" --host 172.16.238.121 --port 502 rdi --quantity 1 --start 10001
    python3 client.py -c "$PLC2_COMM" --host 172.16.238.121 --port 502 rir --quantity 3 --start 30001
    sleep 1
done
