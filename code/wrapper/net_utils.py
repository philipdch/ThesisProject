import socket
import binascii
import struct

PROTOCOLS = {
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

ip_cache = {}

################################################################[ IP HEADER ]################################################################
# Octet|                0 	        |              1 	             |                 2 	            |                 3                 #
# Bit  |    0  1  2  3 	4  5  6  7  |  8  9  10  11  12  13  14  15  |  16 	17 	18 	19 	20 	21 	22 	23  |  24 	25 	26 	27 	28 	29 	30 	31  #
#      |      Version |     IHL 	|            DSCP 	   |  ECN 	 |                            Total length                              #
#      |                     Identification 	                     |      Flags |	              Fragment offset                           #
#      |           Time to Live 	|            Protocol 	         |                            Header checksum                           #
#      |                                                       Source address                                                               #
#      |                                                    Destination address                                                             #
#      |                                                    Options (if IHL > 5)                                                            #
#      |                                                             .                                                                      #
#      |                                                             .                                                                      #
#      |                                                             .                                                                      #
#############################################################################################################################################

####################[ TCP Pseudo-Header ]####################
#  Bit  | 	  0–3    |    4–7    |    8–15    |    16–31    #
#       |                  Source address                   #
#       |               Destination address                 #
#       |          Zeros         |  Protocol  | UDP length  #
#       |       Source port 	              | Dest. port  #
#       |                 Sequence number                   #
#       |             Acknowledgement number                #
#       | Data offset|  Reserved |   Flags 	  |    Window   #
#       |          Checksum 	 |      Urgent pointer      #
#       |                 Options (optional)                # 	 
#       |                       Data                        #
############################################################# 

#####################[ UDP Pseudo-Header]####################
#  Bit  | 	  0–3    |    4–7    |    8–15    |    16–31    #
#       |                  Source address                   #
#       |               Destination address                 #
#       |          Zeros         |  Protocol  | UDP length  #
#       |       Source port 	              | Dest. port  #
#       |        UDP Length 	              | Checksum    #
#       |                      Data                         #
############################################################# 

# Custom class to construct an IP packet with only the minimum information necessary to
# be processed by a wrapper. This is NOT a complete representation of an IP packet and 
# instead contains only the fields, methods and checks required by our application to improve
# performance by allowing faster processing.
class IPPacket:
    def __init__(self, raw_packet):
        self.version_ihl = raw_packet[0] >> 4 
        self.ihl = (raw_packet[0] & 0x0F) * 4 # Internet Header Length, measured in 32-bit words or 4 Byte increments. We multiply by 4 since our packet is stored as a bytearray
        self.total_length = int.from_bytes(raw_packet[2:4], byteorder='big', signed=False)
        self.protocol = PROTOCOLS[raw_packet[9]]
        sip, dip = socket.inet_ntoa(raw_packet[12:16]), socket.inet_ntoa(raw_packet[16:20])
        self.src_ip = sip
        self.dest_ip = dip
        self.checksum = raw_packet[10:12]
        self.payload = raw_packet[self.ihl:]

        self.raw= raw_packet

        ip_cache[sip] = raw_packet[12:16]
        ip_cache[dip] = raw_packet[16:20]

    def set_dest_ip(self, new_ip):
        self.raw[16:20] = ip_cache.get(new_ip, ip_to_bytes(new_ip))

    def get_transport_payload(self):
        if self.protocol == "TCP":
            data_offset = (self.payload[12] >> 4) * 4
            return self.payload[data_offset:]
        elif self.protocol == "UDP":
            return self.payload[8:]

    def set_transport_payload(self, new_payload):
        if self.protocol == "TCP":
            data_offset = self.ihl + ((self.payload[12] >> 4) * 4)
            self.raw[data_offset:] = new_payload
        elif self.protocol == "UDP":
            self.raw[self.ihl + 8:] = new_payload

    def reset_checksum(self):
        self.raw[10:12] = self.ip_checksum().to_bytes(2, byteorder='big') # Delete IP checksum, causing it to be recalculated when the packet is sent
        self.checksum = self.raw[10:12]
        self.total_length = int.from_bytes(self.raw[2:4], byteorder='big', signed=False)
        self.transport_checksum()
        self.payload = self.raw[self.ihl:]

    def calc_checksum(self, data):
        if len(data) % 2 != 0:
            data += b'\x00'  # Pad with zero if the length is odd

        chksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) | data[i + 1]
            chksum += word

        chksum = (chksum >> 16) + (chksum & 0xFFFF)
        chksum = ~chksum & 0xFFFF
        return chksum

    def ip_checksum(self):
        self.raw[10:12] = b'\x00\x00' #Set checksum to 0 before calculation
        self.raw[2:4] = len(self.raw).to_bytes(2, byteorder='big', signed=False) # Update IP total length
        print(f'IP Header = {binascii.hexlify(self.raw[:self.ihl])}')
        return self.calc_checksum(self.raw[:self.ihl])

    def transport_checksum(self):
        src_ip = self.raw[12:16]
        dest_ip = self.raw[16:20]
        if self.protocol == "TCP":
            chksum_offset = self.ihl + 16
            protocol = socket.IPPROTO_TCP
            header_length = (self.raw[self.ihl + 12] >> 4) * 4

        elif self.protocol == "UDP":
            len_offset = self.ihl + 4
            self.raw[len_offset: len_offset + 2] = len(self.raw[self.ihl:]).to_bytes(2, byteorder='big', signed=False)
            chksum_offset = self.ihl + 6
            protocol = socket.IPPROTO_UDP 
            header_length = 8
            
        self.raw[chksum_offset:chksum_offset+2] = b'\x00\x00'
        data = self.raw[self.ihl + header_length:]
        segment_length = header_length + len(data) # Protocol header length + payload length
        pseudo_header = struct.pack('!BBH', 0, protocol, segment_length)
        pseudo_header = src_ip + dest_ip + pseudo_header
        protocol_header = self.raw[self.ihl:self.ihl + header_length]
        pseudo_header = pseudo_header + protocol_header + data
        print(f'PSEUDO HEADER = {binascii.hexlify(pseudo_header)}')
        self.raw[chksum_offset:chksum_offset+2] = self.calc_checksum(pseudo_header).to_bytes(2, byteorder='big')


    def __str__(self):
        return (
            "###[ IP ]###\n"
            f"  version   = {self.version_ihl}\n"
            f"  ihl       = {self.ihl}\n"
            f"  length    = {self.total_length}\n"
            f"  protocol  = {self.protocol}\n"
            f"  src_ip    = {self.src_ip}\n"
            f"  dest_ip   = {self.dest_ip}\n"
            f"  checksum  = {binascii.hexlify(self.checksum)}\n"
            f"  payload   = {binascii.hexlify(self.payload)}\n"
        )

def ip_to_bytes(ip):
    bytes_ip = socket.inet_aton(ip)
    ip_cache[ip] = bytes_ip
    return bytes_ip

def bytes_to_ip(bytes_ip):
    ip = socket.inet_ntoa(bytes_ip)
    return ip