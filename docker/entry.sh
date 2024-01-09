#!/bin/bash

# Enable updates to ARP cache after receiving arp reply
echo 1 > /proc/sys/net/ipv4/conf/all/arp_accept

# Increase ARP cache timeout to allow wrappers to run for the specified time interval
echo 3600 > /proc/sys/net/ipv4/neigh/eth0/gc_stale_time 

# Ignore ICMP Redirect messages and don't send ICMP Redirects
echo 0 > /proc/sys/net/ipv4/conf/all/secure_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects