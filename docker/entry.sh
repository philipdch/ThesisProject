#!/bin/bash

ETHERS="/code/config/ethers"

if [[ "$1" == "debug" ]]; then
    echo "Debug mode. Static ARP disabled."
    shift
else
    if [ -f $ETHERS ]; then
        # Set static ARP cache from ethers file
        arp -f $ETHERS
        echo "Static ARP cache set from $ETHERS"
    else
        echo "Ethers file not found."
    fi
fi

# Enable updates to ARP cache to alow MitM
echo 1 > /proc/sys/net/ipv4/conf/all/arp_accept

# Increase ARP cache timeout to allow wrappers to run for the specified time interval
echo 3600 > /proc/sys/net/ipv4/neigh/eth0/gc_stale_time 

# Ignore ICMP Redirect messages and don't send ICMP Redirects
echo 0 > /proc/sys/net/ipv4/conf/all/secure_redirects 
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects

exec "$@"