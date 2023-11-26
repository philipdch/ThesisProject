echo "Disabling IP forwarding..."
echo 0 > /proc/sys/net/ipv4/conf/all/forwarding
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects

python3 wrapper.py

echo "Re-enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
echo 1 > /proc/sys/net/ipv4/conf/all/send_redirects