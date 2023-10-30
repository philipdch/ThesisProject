import mitm

from scapy.all import *
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import argparse
import json
import ipaddress

KEY = '6755a30834f24886ee88f177d920e0194edc70f03ecd9b67f91e29810eb01c6a'
INIT_VECTOR = '3ffd0c5f236a1713b4feeb9c3af624c4'

WRAPPER_MAC = Ether().src
WRAPPER_IP = get_if_addr("eth0")

KEYS = list(mitm.WRAPPER_MAPPINGS.keys())
VALUES = list(mitm.WRAPPER_MAPPINGS.values())

TRANSPORT_PROTOCOLS = {
    0: "HOPOPT",  # IPv6 Hop-by-Hop Option
    1: "ICMP",    # Internet Control Message Protocol
    2: "IGMP",    # Internet Group Management Protocol
    6: "TCP",     # Transmission Control Protocol
    17: "UDP",    # User Datagram Protocol
    41: "IPv6",   # IPv6 (used in IPv4 headers to indicate encapsulated IPv6)
    47: "GRE",    # Generic Routing Encapsulation
    50: "ESP",    # Encapsulating Security Payload
    51: "AH",     # Authentication Header
    58: "ICMPv6", # ICMP for IPv6
    89: "OSPF",   # Open Shortest Path First (OSPF) Protocol
}

# Encryption of the Transport layer paylaod (TCP or UDP):
#   Receive the packet, extract only the transport layer's payload, if there is one, encrypt and send
#   TCP packets with no paylaod are just forwared. This allows for TCP control messages (SYN, ACK, RST etc) to quickly pass through, 
#   since they don't need to be encrypted
#   The client only needs to decrypt the payload. All other information is already visible
#   Checksums are calculated before packet is sent
def proxy(client):
    def wrapper(packet):
        packet.show()

        # Scapy sniffs all packets passing through an interface. 
        # We need to discard the packets that we just sent with scapy to prvent infinite loop processing
        if packet.haslayer('Ether') and packet['Ether'].src == WRAPPER_MAC:
            print("Picked up own packet. Dropping")
            return

        if not packet.haslayer('IP'):
            return
        
        new_packet = packet['IP']

        sip, dip = packet['IP'].src, packet['IP'].dst

        if (not packet.haslayer('TCP')) and (not packet.haslayer('UDP')):
            print("Packet doesn't have TCP or UDP layer")
            del new_packet['IP'].chksum
            send(new_packet, verbose=False)
            return

        transport_proto = TRANSPORT_PROTOCOLS[packet['IP'].proto]
        print(transport_proto)
        payload = bytes(packet[transport_proto].payload)
        print("PAYLOAD = " + str(payload))
        if payload:
            if sip == client:
                print("Encrypting packet")
                # packet received from client. Wrap it and send it to wrapper's group
                encrypted_payload = encrypt(bytes.fromhex(KEY), bytes.fromhex(INIT_VECTOR), payload)

                # del new_packet['IP'].chksum
                # del new_packet[transport_proto].chksum 

                # print("Forwarding to " + dip + "'s wrapper with MAC: " + mitm.HOST_LIST[KEYS[VALUES.index(dip)]])
                # sendp(Ether(dst = mitm.HOST_LIST[KEYS[VALUES.index(dip)]])/new_packet, verbose=False)
                for wrapper, node in mitm.WRAPPER_MAPPINGS.items():
                    # Avoid forwarding to self
                    if wrapper == WRAPPER_IP:
                        continue
                    
                    # Temporary. Need a way for the receiver to discard packets not addressed to its node
                    if mitm.WRAPPER_MAPPINGS[wrapper] == dip:
                        new_packet[transport_proto].payload = Raw(encrypted_payload + b'\x01')
                    else:
                        new_packet[transport_proto].payload = Raw(encrypted_payload + b'\x00')

                    print("Forwarding to " + node + "'s wrapper with MAC: " + mitm.HOST_LIST[wrapper])
                    new_packet['IP'].dst = node
                    new_packet.show()
                    
                    del new_packet['IP'].len
                    del new_packet['IP'].chksum
                    del new_packet[transport_proto].chksum 
                    if (transport_proto == "UDP"):
                        del new_packet[transport_proto].len

                    # Send a packet with Node target's IP, but its Wrapper's MAC. 
                    # This eliminates the need to poison wrappers, as each wrapper can directly
                    # send packets to other wrappers, while still preserving their transparency
                    sendp(Ether(dst = mitm.HOST_LIST[wrapper])/new_packet, verbose=False)
            elif dip == client:
                print("Decrypting and forwarding to client " + client)

                forward = payload[-1]
                print("Forward? " + str(forward))
                if forward == 1:
                    # packet received from another node to our client. Unwrap it
                    payload = payload[:-1]
                    decrypted_payload = decrypt(bytes.fromhex(KEY), bytes.fromhex(INIT_VECTOR), payload)
                    print(decrypted_payload)

                    new_packet[transport_proto].payload = Raw(decrypted_payload)

                    del new_packet['IP'].len
                    del new_packet['IP'].chksum
                    del new_packet[transport_proto].chksum 
                    if (transport_proto == "UDP"):
                        del new_packet[transport_proto].len

                    new_packet.show()
                    # Don't need to use layer 2 send. Wrapper already knows its node correct MAC
                    send(new_packet, verbose = True)
                else:
                    print("Packet not addressed to client. Dropping")
        else:
            
            del new_packet['IP'].chksum
            del new_packet[transport_proto].chksum 
            print('TCP packet with no payload received. Just forwarding')
            send(new_packet, verbose=False)

    return wrapper

def encrypt(key, initialization_vector, message):
    algorithm = algorithms.AES(key)
    mode = modes.CTR(initialization_vector)

    cipher = Cipher(algorithm, mode)
    encryptor = cipher.encryptor()

    return encryptor.update(message) + encryptor.finalize()

def decrypt(key, initialization_vector, message):
    algorithm = algorithms.AES(key)
    mode = modes.CTR(initialization_vector)

    cipher = Cipher(algorithm, mode)

    decryptor = cipher.decryptor()
    return decryptor.update(message) + decryptor.finalize()

def main():
    parser = argparse.ArgumentParser(prog="Wrapper", 
                                     description='Wrapper that acts as a transparent proxy. Intercepts packets from the client \
                                        processes them and forwards them to the correct destination where they will be \
                                        intercepted again by the corresponding wrapper'
                                    )
    parser.add_argument('--config', '-c',
                    help='the path to the wrapper\'s configuration file')
    # subparsers = parser.add_subparsers(help='Launch an ARP poison attack to make the wrapper act as a proxy between the client \
    #                                     and the other nodes. This is necessary for the wrapper to function properly. Use this if \
    #                                     you don\'t intent to use another tool for this job (e.g. ettercap)')
    
    # mitm_parser = subparsers.add_parser('mitm', 
    #                                     help='Launch an ARP poison attack against the client')

    # mitm_parser.add_argument('--network', 
    #                          help='The client\'s network address or subnet mask (e.g. 192.168.0.0/24 OR /24)')

    # parser.parse_args(['--client', 'mitm', '--network'])
    # parser.add_argument('--wrappers', nargs='*', default=[], help= 'the IPs of the wrappers in the network')
    # args = parser.parse_args()
    # file = args.config
    CLIENT_IP = os.environ['CLIENT']
    GROUP = [x.strip() for x in os.environ["WRAPPER-GROUP"].split(',')]

    mitm.discovery(WRAPPER_IP + "/24")

    for ip in mitm.HOST_LIST.keys():
        try:
            mitm.HOST_LIST[ip] = mitm.get_mac(ip)    
        except Exception:
            print("Couldn't Find MAC Address for target" + ip)

    for target_ip in mitm.HOST_LIST.keys():
        if target_ip != CLIENT_IP:
            if target_ip not in GROUP:
                mitm.one_way_poison(CLIENT_IP, target_ip)
            else:
                mitm.arp_poison(CLIENT_IP, target_ip)
    print("Targets poisoned successfully")

    try:
        sniff(prn=proxy(CLIENT_IP))
    except KeyboardInterrupt:
        pass
        # for target_ip in mitm.HOST_LIST.keys():
        #     if target_ip != CLIENT_IP:
        #         mitm.restore_tables(CLIENT_IP, target_ip)

if __name__=="__main__":
    main()