import socket
import struct
import textwrap


def main():
    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(3))
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


main()

































