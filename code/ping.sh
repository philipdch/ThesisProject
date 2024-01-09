#!/bin/bash

ATTEMPTS=5
IP_FILE="./ip_list.txt"

trap 'echo -e "Exiting"; exit 1' SIGINT

usage() {
    echo "Usage: $0 [attempts]"
    echo "Where 'attempts' is the number of arp probes to send before moving to the next destination (default: $ATTEMPTS)"
    exit 1
}

is_integer() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

if [ ! -f "$IP_FILE" ]; then
    echo "File '$IP_FILE' not found."
    exit 1
fi

DESTINATIONS=($(cat "$IP_FILE"))

if [ "$#" -eq 1 ]; then
    if ! is_integer "$1"; then
        echo "Attempt number must be an integer."
        usage
    fi
    attempts=$1
else
    attempts=$DEFAULT_ATTEMPTS
fi

for ip in "${DESTINATIONS[@]}"; do
    echo "Pinging $ip..."
    if arping -f -c $attempts $ip; then
        echo "Reply received"
    else
        echo "No reply from $ip."
    fi
done

exit 0