import mitm

from scapy.all import *
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import argparse
import json

KEY = '6755a30834f24886ee88f177d920e0194edc70f03ecd9b67f91e29810eb01c6a'
INIT_VECTOR = '3ffd0c5f236a1713b4feeb9c3af624c4'

def proxy(client, group):
    def wrapper(packet):

        if not packet.haslayer('IP'):
            return

        if not packet.haslayer('TCP'):
            return 

        payload = packet['TCP'].payload
        if payload:
            sip = packet['IP']
            dip = packet['IP']

            if sip == client:
                # packet received from client. Wrap it and send it to wrapper's group
                encrypted_payload = encrypt(bytes.fromhex(KEY), bytes.fromhex(INIT_VECTOR), bytes(payload))
                for ip in group:
                    new_packet = IP(dst=ip, src=packet['IP'].src)
                    new_packet['IP'].payload = packet['IP'].payload
                    new_packet['TCP'].payload = Raw(encrypted_payload)
                    
                    del new_packet['IP'].chksum
                    del new_packet['TCP'].chksum 

                    send(new_packet)
            elif dip == client:
                # packet received from another node to our client. Unwrap it
                decrypted_payload = decrypt(bytes.fromhex(KEY), bytes.fromhex(INIT_VECTOR), new_packet['TCP'].payload.load)
                print(decrypted_payload)
                new_packet = IP(dst=client, src=packet['IP'].src)
                new_packet['TCP'].payload = Raw(decrypted_payload)

                del new_packet['IP'].chksum
                del new_packet['TCP'].chksum 

                send(new_packet)

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
    GROUP = os.environ["WRAPPER-GROUP"]
    subnet = "/24"

    network = CLIENT_IP + subnet
    mitm.discovery(network)

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
        sniff(prn=proxy(CLIENT_IP, GROUP))
    except KeyboardInterrupt:
        for target_ip in mitm.HOST_LIST.keys():
            if target_ip != CLIENT_IP:
                mitm.restore_tables(CLIENT_IP, target_ip)

if __name__=="__main__":
    main()