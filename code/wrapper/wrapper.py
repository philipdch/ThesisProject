import mitm
from net_utils import *
from encryption import encrypt, decrypt, read_key

from scapy.all import *
from pyJoules.energy_meter import measure_energy
from pyJoules.handler.csv_handler import CSVHandler

import binascii
import os
import argparse
import json
import time

l2_socket = conf.L2socket(iface='eth0')
l3_socket = conf.L3socket(iface='eth0')

packets = []
    
PRIVATE_KEY = '' # Wrapper's private key

WRAPPER_MAC = Ether().src
WRAPPER_IP = get_if_addr("eth0")
wrapper_id = WRAPPER_IP.split(".")[-1]

csv_handler = CSVHandler('./performance/fun_wrapper_cons_' + wrapper_id + '.csv')

PKEY_MAPPINGS = {} # client_ip:RsaKey

def load_group(group_id):
    try:
        with open('groups.json', 'r') as file:
            return json.load(file)['groups'][group_id]
    except FileNotFoundError:
        print(f"Error: JSON file not found")
        return []

def load_pub_key(key_path):
    try:
        return read_key(key_path)
    except FileNotFoundError as ex:
        print("Error: Public Key file not found")
        return None

def load_private_key(key_path):
    try:
        return read_key(key_path)
    except FileNotFoundError:
        print("Error: Private Key file not found")
        return None

def update_timings(pkt, received_time, sent_time, exec_time):
    packet_timings = {
                    'id':len(packets),
                    'packet': pkt,
                    'received_time': received_time,
                    'sent_time': sent_time,
                    'func_exec_time': exec_time
                }
    packets.append(packet_timings)

def write_log():
    for entry in packets:
        pkt = IP(entry['packet'])
        entry['packet'] = pkt.summary()
    log_filename = './performance/log_' + wrapper_id + '.json'
    with open(log_filename, 'w') as log_file:
        print("\nWriting log as " + log_filename)
        json.dump(packets, log_file)
        print("Log saved")

def cleanup(client_ip):
    for target_ip in mitm.host_list.keys():
        if target_ip != client_ip:
            mitm.restore_tables(client_ip, target_ip)

def proxy(client, group):
    '''Handles a sniffed packet: Encrypts or decrypts the transport layer payload (TCP or UDP), and forwards it.

    Only handles TCP or UDP packets. All other packets, which do not contain meaningful communication data and thus 
    do not need to be processed further are dropped immediately, to improve the wrapper's efficiency.

    For each received packet:
    1) Extracts the Transportt Layer payload.
    2) Checks the source and destination address:
        a) If the packet is sent from the wrapper's client, it is address to another node in the network.
            The payload is encrypted using the destination's wrapper's public key and the packet is forwarded 
            to every wrapper in the wrapper's group.
            If no payload exists, the packet is simply forwarded, allowing for quick processing of TCP 
            control messages (SYN, ACK, RST, etc.).
        b) If the packet is addressed to the client, the wrapper attempts to decrypt it using its private key.
            If decryption is successful the client was the original recipient and the packet is forwarded. 
            Otherwise the packet is dropped.
    3) A log entry containing the arrival time, sent time and total processing time of the packet is created.

    Performance Considerations:
    a) Reuses the same socket to send all packets. Scapy's send function opens and closes a new socket each time a 
        packet is sent. By keeping a socket open throughout the wrapper's operation, processing times are reduced tremendously.
    b) Disables Scapy's dissection of packet layers, limiting processing to bytearrays for efficiency.
        Only the Ether layer of the received packet is decoded while its encapsulated payload is treated as a bytearray. 
        After that we keep a simplified IPPacket object to perform the necessary operations directly on the bytearray. Since 
        we do not need a human-readable representation of the packet, this approach further improves performance by 1) not 
        decoding layers that we do not need and 2) not needing to convert the packet back to raw bytes each times it is
        ready to be sent.

    Warning! Before each packet can be sent, all IP and TCP/UDP checksums need to be calculated. An error in the packet's checksum
             may cause it to be dropped after the application hands it over to the kernel.

    Args:
        client (str): IP address of the wrapper's client.
        group (list): List of other wrappers in the group.

    Returns:
        function: Function for handling sniffed packets that can be given to scapy's sniff function.
    '''

    @measure_energy(handler=csv_handler)
    def wrapper(packet):
        start_time = time.perf_counter()
        packet.show()

        if packet.haslayer('Ether') and packet['Ether'].type == 0x0800:
            try:
                ip_packet = IPPacket(bytearray(packet['Raw'].load))
                print(ip_packet)
            except ValueError as e:
                print(e)
                return
        else:
            print('Packet has no IP layer')
            return
        
        received_time = packet.time
        payload = ip_packet.get_transport_payload()
        print("PAYLOAD = " + str(binascii.hexlify(payload)))
        sent_time = 0
        if ip_packet.src_ip == client:
            # packet received from client. Wrap it and send it to wrapper's group
            if payload:
                print("Encrypting packet, with " + ip_packet.dest_ip + " wrapper's key")
                encrypted_payload = encrypt(payload, PKEY_MAPPINGS[ip_packet.dest_ip]) # Encrypt payload using the destination's wrapper's public key.
                print("Encrypted Message is:", binascii.hexlify(encrypted_payload))
                ip_packet.set_transport_payload(encrypted_payload)
            elif(ip_packet.protocol == 'TCP' and (ip_packet.payload[13] & 0x04) != 0):
                # Avoid resetting original connection
                # Could just drop RST
                print('Forwarding RST only to original destination.')
                ip_packet.reset_checksum()
                dest_mac = mitm.host_list.get(ip_packet.dest_ip, "ff:ff:ff:ff:ff:ff")
                eth_frame = Ether(dst = dest_mac, type=0x0800)
                eth_frame = bytearray(raw(eth_frame)) + ip_packet.raw
                l2_socket.send(eth_frame)
                sent_time = time.time()
                update_timings(ip_packet.raw, received_time, sent_time, None)
                return

            for wrapper in group:
                wrapper_mac = mitm.host_list.get(wrapper, None)
                
                # Avoid forwarding to self or to unknown destination
                if (wrapper == WRAPPER_IP) or (not wrapper_mac):
                    continue

                wrapper_client = mitm.WRAPPER_MAPPINGS[wrapper]
                
                ip_packet.set_dest_ip(wrapper_client)
                print("Forwarding to " + wrapper_client + "'s wrapper with MAC: " + wrapper_mac)

                # Send a packet with Node target's IP, but its Wrapper's MAC. 
                # This eliminates the need to poison wrappers, as each wrapper can directly
                # send packets to other wrappers, while still preserving their transparency
                ip_packet.reset_checksum()
                eth_frame = Ether(dst = wrapper_mac, type=0x0800)
                eth_frame = bytearray(raw(eth_frame)) + ip_packet.raw
                print(ip_packet)
                l2_socket.send(eth_frame)
                sent_time = time.time()
                update_timings(ip_packet.raw, received_time, sent_time, None)
        elif ip_packet.dest_ip == client:
            print("Decrypting and forwarding to client " + client)
            # Try to decrypt packet using the PKCS#1_OAEP cipher. Decryption will either:
            # a) Succeed. This means the message was encrypted using the wrapper's public key,
            #          therefore it is addressed to the node behind it. We need to forward it.
            # b) Fail. Similarly, the payload was encrypted with another node's public key.
            #          In this case, we simply drop the packet.
            if payload:
                try:
                    decrypted_payload = decrypt(payload, PRIVATE_KEY)
                    ip_packet.set_transport_payload(decrypted_payload)
                except ValueError as ex:
                    print("Decryption failed: Wrong private key, dropping packet")
                    return
                except TypeError as ex:
                    print("Decryption failed: Used public key, dropping packet")
                    return
                
            ip_packet.reset_checksum()
            print(ip_packet)
            dest_mac = mitm.host_list.get(client, "ff:ff:ff:ff:ff:ff")
            eth_frame = Ether(dst = dest_mac, type=0x0800)
            eth_frame = bytearray(raw(eth_frame)) + ip_packet.raw
            l2_socket.send(eth_frame)
            sent_time = time.time()
        else:
            return
        
        end_time = time.perf_counter()
        execution_time = end_time - start_time # The time it took for the wrapper to execute after receiving a (valid) packet 
        if (packets and packets[-1]['func_exec_time'] is None):
                # If execeution time of last packet is none, the packet belongs to the list of packets forwarded to a group.
                # Execution time is calculated and assigned to the last forwarded packet.
                packets[-1]['func_exec_time'] = execution_time
        else:
            update_timings(ip_packet.raw, received_time, sent_time, execution_time)

    return wrapper

def main(args):
    # client_ip = args.client_ip
    gid = args.group_number
    client_ip = os.environ['CLIENT']

    # Get wrapper's group from json file
    group = load_group(gid)

    # Read wrapper's private key
    global PRIVATE_KEY
    private_key_path = os.path.join(os.path.dirname(__file__), '..', '.ssh', 'id_rsa')
    PRIVATE_KEY = load_private_key(private_key_path)

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
    # Note: All hosts must be discovered prior to the execution of the wrapper
    # Otherwise, various issues may arise (e.g. packet loss due to unknown recipient)
    if args.mitm:
        # Discover active hosts dynamically. Slower and may discover hosts outside the application's scope
        mitm.discovery(WRAPPER_IP + "/24")
    else:
        # Discover hosts based on a known list.
        # Sends as many requests in a specific time window to allow hosts to come up and join the network.
        # If any host is determined to be unreachable, the wrapper exits
        for wrapper, client in mitm.WRAPPER_MAPPINGS.items():
            if(wrapper == WRAPPER_IP):
                result1 = WRAPPER_MAC
            else:
                result1 = mitm.persistent_discovery(wrapper)
            result2 = mitm.persistent_discovery(client)

            if(result1 is None or result2 is None):
                print("Exiting")
                return
            mitm.host_list[wrapper] = result1
            mitm.host_list[client] = result2
    print("Hosts:")
    print(json.dumps(mitm.host_list, indent=2))

    for host in PKEY_MAPPINGS:
        # Read the wrappers' public keys
        key_name = PKEY_MAPPINGS[host]
        print(f'Loading pub key: {key_name}')
        key_path = os.path.join(public_keys_path, key_name)
        PKEY_MAPPINGS[host] = load_pub_key(key_path)

    if args.mitm:
        for host in mitm.host_list.keys():
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
        print("Start sniffing")
        conf.layers.filter([Ether]) # Specify which layers will be dissected by scapy. More layers increase the delay needed to process a packet
        bpf = f"ether src not {WRAPPER_MAC} && not arp" # Filter packets on the OS level to improve performance
        sniffer = AsyncSniffer(prn=proxy(client_ip, group), filter=bpf, store=False) #Use AsyncSniffer which doesn't block
        sniffer.start()
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
        conf.layers.unfilter()
        write_log()
        print("Writing energy consumption results as CSV")
        csv_handler.save_data()
        if args.mitm:
            cleanup(client_ip)

if __name__=="__main__":
    parser = argparse.ArgumentParser(prog="Wrapper", 
                                     description='Wrapper that acts as a transparent proxy. Given a group of wrappers: \n \
                                        a) encrypts packets from the client and forwards them to the group, and \n \
                                        b) Decrypts the packets received from the group and forwards them to the client.'
                                    )

    parser.add_argument('-g', '--gid', dest='group_number', required=True, help="Wrapper's group id. Must be defined in the 'groups.json' file")
    parser.add_argument('-c', '--cip', dest='client_ip', help="The IP of the wrapper's client. Only one wrapper may be assigned to a client")
    parser.add_argument('-m', '--mitm', dest='mitm', help='Poison client to dynamically alter its ARP cache. \
                                                        Use this option when static ARP entries are not configured')
    args = parser.parse_args()
    main(args)