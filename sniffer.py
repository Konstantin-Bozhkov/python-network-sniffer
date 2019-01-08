import socket
import struct
import textwrap


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, address = connection.recvfrom(65536)
        desc_mac, src_mac, ethernet_proto, data = ethernet_frame(raw_data)

        print('\nEthernet frame:')
        print('Destination:{}, Source:{}, Protocol:{}'.format(desc_mac,src_mac,ethernet_proto))


# Unpack ethernet frame
def ethernet_frame(data):
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(destination_mac), get_mac_addr(source_mac), socket.htons(protocol),data[14:]

# return the formated mac address ie AA:BB:CC:DD:EE:FF
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format,bytes_addr)
    mac_address = ':'.join(bytes_str).upper()
    return mac_address

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15 ) * 4

    ttl, ip_protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version,header_length, ttl, ip_protocol, ipv4(src), ipv4(target), data[header_length:] # data[] starts from the end of the header length

#127.0.0.0.1
# Return  formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str,addr))



# Unpack ICMP packets
def  unpack_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def unpack_tcp(data):
    (source_port, destination_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H ',data[:14])

main()

































