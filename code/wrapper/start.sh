#!/bin/bash

LOCAL_IP=$(hostname -I | awk '{print $1}')
container_ips=( "110" "111" "112" "120" "121" "122" "123" "124" "10" "11" "12" "20" "21" "22" "23" "24")

ATTEMPTS=3

host_is_up() {
    if [ "$1" == "$LOCAL_IP" ]; then
        return 0
    fi

    arping -c 1 $1 > /dev/null 2>&1
    return $?
}

# for ip in "${container_ips[@]}"; do
#     retries=0
#     host=172.16.238.$ip

#     while [ $retries -lt $ATTEMPTS ]; do
#         host_is_up $host

#         if [ $? -eq 0 ]; then
#             echo "$host is up."
#             break
#         else
#             echo "$host is not up. Retrying..."
#             ((retries++))
#         fi

#         if [ $retries -eq $ATTEMPTS ]; then
#             echo "Failed to reach $host after $ATTEMPTS attempts. Exiting."
#             exit 1
#         fi

#         sleep 10
#     done
# done

echo "All containers are up. Running Wrapper."
echo "Disabling IP forwarding..."
echo 0 > /proc/sys/net/ipv4/conf/all/forwarding
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
python3 wrapper.py --gid $1

echo "Re-enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
echo 1 > /proc/sys/net/ipv4/conf/all/send_redirects