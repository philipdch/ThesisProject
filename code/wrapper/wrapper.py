import mitm
from encryption import encrypt, decrypt, read_key

from scapy.all import *
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse

import binascii
import os
import argparse
import json
import time

packets = []
    
PRIVATE_KEY = '' # Wrapper's private key

WRAPPER_MAC = Ether().src
WRAPPER_IP = get_if_addr("eth0")

PKEY_MAPPINGS = {} # client_ip:RsaKey

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
def proxy(client, group):
    def wrapper(packet):
        start_time = time.perf_counter()
        packet.show()

        # Scapy sniffs all packets passing through an interface, including the ones it sends. 
        # We need to discard the packets that we just sent with scapy to prvent infinite loop processing
        if packet.haslayer('Ether') and packet['Ether'].src == WRAPPER_MAC:
            print("Picked up own packet. Dropping")
            return

        if not packet.haslayer('IP'):
            return
        
        new_packet = packet['IP']
        sip, dip = packet['IP'].src, packet['IP'].dst

        # Process only packets that have a TCP or UDP layer, commonly used for every application protocol we examanied
        if (not packet.haslayer('TCP')) and (not packet.haslayer('UDP')):
            print("Packet doesn't have TCP or UDP layer")
            del new_packet['IP'].chksum
            send(new_packet, verbose=False)
            return

        transport_proto = TRANSPORT_PROTOCOLS[packet['IP'].proto] # Get the transport layer protocol 
        print(transport_proto)
        payload = bytes(packet[transport_proto].payload)
        print("PAYLOAD = " + str(payload))
        sent_time = 0
        if payload:
            # The packet's payload is encrypted using the destination's wrapper's public key.
                # This ensures that the packet may be safely forwarded to every other node in the group
                # but only the original recipient's wrapper will be able to decipher it and forward it to it.
                # For every other wrapper, the decryptiom will fail, prompting them to drop the packet
            if sip == client:
                # packet received from client. Wrap it and send it to wrapper's group
                print("Encrypting packet, with " + dip + " wrapper's key")
                encrypted_payload = encrypt(payload, PKEY_MAPPINGS[dip])
                print("Encrypted Message is:", binascii.hexlify(encrypted_payload))
                new_packet[transport_proto].payload = Raw(encrypted_payload)

                for wrapper in group:
                    wrapper_client = mitm.WRAPPER_MAPPINGS[wrapper]

                    # Avoid forwarding to self
                    if wrapper == WRAPPER_IP:
                        continue
                    
                    print("Forwarding to " + wrapper_client + "'s wrapper with MAC: " + mitm.HOST_LIST[wrapper])
                    new_packet['IP'].dst = wrapper_client
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
                    sent_time = time.time()
                    packet_timings = {
                        'packet': new_packet.copy(),
                        'received_time': new_packet.time,
                        'sent_time': sent_time,
                        'func_exec_time': None
                    }
                    packets.append(packet_timings)
            elif dip == client:
                # packet received from another node to our client.
                # Try to decrypt packet using the PKCS#1_OAEP cipher. Decryption will either:
                # Succeed. This means the message was encrypted using the wrapper's public key,
                #          therefore it is addressed to the node behind it. We need to forward it.
                # b) Fail. Similarly, the payload was encrypted with another node's public key.
                #          In this case, we simply drop the packet.
                print("Decrypting and forwarding to client " + client)
                try:
                    decrypted_payload = decrypt(payload, PRIVATE_KEY)
                    print(decrypted_payload)

                    new_packet[transport_proto].payload = Raw(decrypted_payload)

                    del new_packet['IP'].len
                    del new_packet['IP'].chksum
                    del new_packet[transport_proto].chksum 
                    if (transport_proto == "UDP"):
                        del new_packet[transport_proto].len

                    new_packet.show()
                    # Don't need to use layer 2 send. Wrapper already knows its node's correct MAC
                    send(new_packet, verbose = True)
                    sent_time = time.time()
                except ValueError as ex:
                    print("Decryption failed: Wrong private key, dropping packet")
                except TypeError as ex:
                    print("Decryption failed: Used public key, dropping packet")
        else:
            
            del new_packet['IP'].chksum
            del new_packet[transport_proto].chksum 
            print('Packet with no payload received. Just forwarding')
            send(new_packet, verbose=False)
            sent_time = time.time()

        end_time = time.perf_counter()
        execution_time = end_time - start_time # The time it took for the wrapper to execute after receiving a (valid) packet 
        if (packets and packets[-1]['func_exec_time'] is None):
                # If execeution time of last packet is none, packet belongs to the list of packets forwarded to a group.
                # Execution time is calculated and assigned to the last packet forwarded
                packets[-1]['func_exec_time'] = execution_time
        else:
            packet_timings = {
                'packet': new_packet,
                'received_time': new_packet.time,
                'sent_time': sent_time,
                'func_exec_time': execution_time
            }
            packets.append(packet_timings)

    return wrapper

def main():
    parser = argparse.ArgumentParser(prog="Wrapper", 
                                     description='Wrapper that acts as a transparent proxy. Intercepts packets from the client \
                                        processes them and forwards them to the wrapper\'s group where they will be \
                                        intercepted again by the corresponding wrapper'
                                    )
    # parser.add_argument('--cip', dest='client_ip', required=True, help="Client's IP address")

    parser.add_argument('--gid', dest='group_number', required=True, help="Wrapper's group id. Must be defined in the 'groups.json' file")

    # Parse the command line arguments
    args = parser.parse_args()

    # client_ip = args.client_ip
    gid = args.group_number
    client_ip = os.environ['CLIENT']

    # Get wrapper's group from json file
    group=[]
    try:
        with open('groups.json', 'r') as file:
            group = json.load(file)['groups'][gid]
    except FileNotFoundError:
        print(f"Error: JSON file not found")

    # Read wrapper's private key
    private_key_path = os.path.join(os.path.dirname(__file__), '..', '.ssh', 'id_rsa')
    try:
        global PRIVATE_KEY
        PRIVATE_KEY = read_key(private_key_path)
    except FileNotFoundError:
        print("Error: Private Key file not found")

    # Read public keys and map them to their respective wrappers
    public_keys_path = os.path.join(os.path.dirname(__file__), '..', '.ssh/common')
    mappings_path = os.path.join(public_keys_path, 'hosts.json')
    global PKEY_MAPPINGS
    try:
        with open(mappings_path, 'r') as file:
            PKEY_MAPPINGS = json.load(file)['hostMappings'] # <host_ip:key_path>
    except FileNotFoundError:
        print(f"Error: JSON file not found at {mappings_path}")
    
    # Discover active hosts on the local network
    mitm.discovery(WRAPPER_IP + "/24")

    for host in mitm.HOST_LIST.keys():
        # Read the wrappers' public keys
        if host in PKEY_MAPPINGS:
            key_name = PKEY_MAPPINGS[host]
            key_path = os.path.join(public_keys_path, key_name)
            try:
                PKEY_MAPPINGS[host] = read_key(key_path)
            except FileNotFoundError as ex:
                print("Error: Public Key file for host '" + host + "' not found")

        if host != client_ip:
            # If the target is not a wrapper we need to one-way poison it so that only
            #   our client forwards traffic intended for them through us, but we don't change 
            #   the target node's arp cache, since another wrapper is responsible for it
            # Otherwise, we need to poison the client and the target, in order to appear
            #   transparent to both of them.
            if host not in mitm.WRAPPER_MAPPINGS:
                mitm.one_way_poison(client_ip, host)
            else:
                mitm.arp_poison(client_ip, host)
    print("Targets poisoned successfully")

    try:
        sniffer = AsyncSniffer(prn=proxy(client_ip, group)) #Use AsyncSniffer which doesn't block
        sniffer.start()
        sniffer.join()
        # sniff(prn=proxy(client_ip, group))
    except KeyboardInterrupt:
        sniffer.stop()
        print("Writing log")
        wrapper_id = WRAPPER_IP.split(".")[-1]
        log_filename = 'log_' + wrapper_id + '.txt'
        with open(log_filename, 'w') as log_file:
            for packet_info in packets:
                log_file.write(f"Packet Info:\n")
                log_file.write(f"Packet:\n{packet_info['packet']}\n")
                log_file.write(f"Received Time: {packet_info['received_time']}\n")
                log_file.write(f"Sent Time: {packet_info['sent_time']}\n")
                log_file.write(f"Function Execution Time: {packet_info['func_exec_time']}\n")
                log_file.write("\n")
        # for target_ip in mitm.HOST_LIST.keys():
        #     if target_ip != CLIENT_IP:
        #         mitm.restore_tables(CLIENT_IP, target_ip)

if __name__=="__main__":
    main()