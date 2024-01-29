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

ip_cache = {} # ip_string:ip_bytes

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

class IPPacket:
    '''Custom IP packet represetation. Contains only the minimum information necessary to allow
    fast processing and thus is not a complete representation of all the layers contained 
    within the packet.

    Args:
        raw_packet (bytes): Byte representation of an IP packet

    Attributes:
        version_ihl (int): Internet Protocol Version
        ihl (int): Length of IP header
        total_length (int): Length of IP packet, including header and data
        protocol (int): Protocol encapsulated in the IP packet
        src_ip (string): Source Address
        dest_ip (string): Destination Address
        checksum (bytes): Packet checsum
        payload (bytes): Data portion of the packet (includes transport layer header)
    
    Raises:
        ValueError: If the transport protocol is neither "TCP" nor "UDP".
    '''

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
        
        # Process only TCP or UDP packets to avoid unecessary processing
        # of ICMP or similar messages that shouldn't be forwarded by our
        # application
        if self.protocol == "TCP":
            self.data_offset = ((self.payload[12] >> 4) * 4)
        elif self.protocol == "UDP":
            self.data_offset = 8
        else:
            raise ValueError("Only TCP or UDP payloads are supported")

        self.raw= raw_packet

        ip_cache[sip] = raw_packet[12:16]
        ip_cache[dip] = raw_packet[16:20]

    def set_dest_ip(self, new_ip):
        self.raw[16:20] = ip_cache.get(new_ip, ip_to_bytes(new_ip))

    def get_transport_payload(self):
        return self.payload[self.data_offset:]

    def set_transport_payload(self, new_payload):
        self.raw[self.ihl + self.data_offset:] = new_payload

    def reset_checksum(self):
        ''' Reset and re-calculate IP and Transport Layer (TCP/UDP) checksums.

        The checksums should be manually resetted every time the packet is ready to be sent.
        Failure to calculate the checksums will cause the packet to be dropped by the Kernel,
        even though the "send" function may report the transmission to be successful (since 
        the Transport Layer and below are handled separately by the Kernel).
        '''

        self.raw[10:12] = self.__ip_checksum().to_bytes(2, byteorder='big') # Delete IP checksum, causing it to be recalculated when the packet is sent
        self.checksum = self.raw[10:12]
        self.total_length = int.from_bytes(self.raw[2:4], byteorder='big', signed=False)
        self.__transport_checksum()
        self.payload = self.raw[self.ihl:]

    def __calc_checksum(self, data):
        ''' Generic 16-bit one's complement checksum calculation.

        The checksum is defined as the 16 bit one's complement of the one's
        complement sum of all 16 bit words in the provided data. Simply put,
        it is the sum of all 2-byte words in 1's complement represenation.
        '''

        if len(data) % 2 != 0:
            data += b'\x00'  # Pad with zero if the length is odd

        chksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) | data[i + 1] # Get 16-bit word
            chksum += word

        chksum = (chksum >> 16) + (chksum & 0xFFFF) # Add end-around carry back to the result, if it occurs
        chksum = ~chksum & 0xFFFF # Convert result to 16-bit 1's complement 
        return chksum

    def __ip_checksum(self):
        ''' Calculate the checksum of the IP header, as described in RFC 791.

        The IP checksum is calculated only on the IP header, by setting the
        checksum to zero prior to the calculation.
        '''

        self.raw[10:12] = b'\x00\x00' #Set checksum to 0 before calculation
        self.raw[2:4] = len(self.raw).to_bytes(2, byteorder='big', signed=False) # Update IP total length
        print(f'IP Header = {binascii.hexlify(self.raw[:self.ihl])}')
        return self.__calc_checksum(self.raw[:self.ihl])

    def __transport_checksum(self):
        ''' Calculate the TCP or UDP checksum as defined RFC 9293 or RFC 768 respectively.

        The checksum is calculated on the pseudo-header of each protocol and set to zero 
        before the calculation. In the case of UDP, the segment's length is re-calculated 
        to account for changes in the payload.
        '''

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
        self.raw[chksum_offset:chksum_offset+2] = self.__calc_checksum(pseudo_header).to_bytes(2, byteorder='big')


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
    ''' Convert string representation of IP to bytes '''
    bytes_ip = socket.inet_aton(ip)
    ip_cache[ip] = bytes_ip # Cache result
    return bytes_ip

def bytes_to_ip(bytes_ip):
    ''' Convert byte representation of IP to string '''
    ip = socket.inet_ntoa(bytes_ip)
    return ip