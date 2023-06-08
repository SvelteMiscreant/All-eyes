import socket
import struct

def packet_sniffer():
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = sniffer.recvfrom(65536)

        eth_length = 14
        eth_header = raw_data[:eth_length]
        eth = struct.unpack('! 6s 6s H', eth_header)
        src_mac = get_mac_address(eth[1])
        dest_mac = get_mac_address(eth[0])

        print("Source MAC: " + src_mac)
        print("Destination MAC: " + dest_mac)

        ip_header = raw_data[eth_length:eth_length + 20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])

        print("Source IP: " + src_ip)
        print("Destination IP: " + dest_ip)

        print("-------------------")

def get_mac_address(mac_bytes):
    mac_string = map('{:02x}'.format, mac_bytes)
    return ':'.join(mac_string)

packet_sniffer()
