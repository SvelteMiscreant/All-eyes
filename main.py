import socket
import struct

def get_protocol_name(protocol):
    	protocol_names = {
    		0: "HOPOPT",
    		1: "ICMP",
    		2: "IGMP",
    		3: "GGP",
    		4: "IPv4",
    		6: "TCP",
    		17: "UDP",
    		84: "IPTM",
    	}
    	return protocol_names.get(protocol, "Unknown")

def packet_analyse(header, data):
	eth_length = 14
	eth_header = data[:eth_length]
	eth = struct.unpack('! 6s 6s H', eth_header)
	src_mac = get_mac_address(eth[1])
	dest_mac = get_mac_address(eth[0])

	print("Source MAC: ", src_mac)
	print("Destination MAC: ", dest_mac)

	ip_header = data[eth_length:eth_length + 20]
	iph = struct.unpack('!BBHHHBBH4s4s', ip_header) # Extracted IP header in correct tuple format
	version_ihl = iph[0] # First byte of IPH is version of Internet Header Length
	ihl = version_ihl & 0xF # Last four bits are the Internet Header Length
	iph_length = ihl * 4
	src_ip = socket.inet_ntoa(iph[8]) # Making the source IP Address human readable
	dest_ip = socket.inet_ntoa(iph[9])
	protocol = iph[6] # Protocol extracted from IP Header tuple
	protocol_name = get_protocol_name(protocol)
    
	print("Source IP: ", src_ip)
	print("Destination IP: ", dest_ip)
	print("Protocol Value: ", str(protocol))
	print("Protocol: ", protocol_name)

	print("-------------------")

def packet_sniffer():
	sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	while True:
		rawdata, addr = sniffer.recvfrom(65536)
		packet_analyse(None, rawdata)

def get_mac_address(mac_bytes):
    mac_string = map('{:02x}'.format, mac_bytes)
    return ':'.join(mac_string)

packet_sniffer()
