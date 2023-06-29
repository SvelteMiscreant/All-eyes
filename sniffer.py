import subprocess
import socket
import struct

def validate_port(port):
    try:
        port = int(port)
        if port < 0 or port > 65535:
            raise ValueError
        return port
    except ValueError:
        print('Invalid port number: ', port, '. Port must be a positive integer between 0 and 65535.')
        return None

# Port filter function

def filter_inport(port):
	command = ['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', port, '-j', 'DROP']
	subprocess.run(command)
	
def filter_outport(port):
	command = ['sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', port, '-j', 'DROP']
	subprocess.run(command)

def filter_port():
	inports = input('Which incoming ports would you like to block? Separate by spaces.\n')
	outports = input('Which outgoing ports would you like to block? Separate by spaces.\n')
	inport_list = inports.split(' ')
	outport_list = outports.split(' ')
	
	for inport in inport_list:
		inport = validate_port(inport.strip())
		if inport:
			filter_inport(inport)
			print('Incoming port ', inport, ' is blocked.\n')
			
	for outport in outport_list:
		outport = validate_port(outport.strip())
		if outport:
			filter_outport(outport)
			print('Outgoing port ', outport, ' is blocked.\n')
	
# Port open function
	
def open_inport(port):
	command = ['sudo', 'iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', port, '-j', 'DROP']
	subprocess.run(command)
	
def open_outport(port):
	command = ['sudo', 'iptables', '-D', 'OUTPUT', '-p', 'tcp', '--dport', port, '-j', 'DROP']
	subprocess.run(command)

def open_port():
	inports = input('Which incoming ports would you like to open? Separate by spaces.\n')
	outports = input('Which outgoing ports would you like to open? Separate by spaces.\n')
	inport_list = inports.split(' ')
	outport_list = outports.split(' ')
	
	for inport in inport_list:
		inport = validate_port(inport.strip())
		if inport:
			open_inport(inport)
			print('Incoming port ', inport, ' is open.\n')
			
	for outport in outport_list:
		outport = validate_port(outport.strip())
		if outport:
			open_outport(outport)
			print('Outgoing port ', outport, ' is open.\n')

def get_protocol_name(protocol):
	protocol_names = {
		0: 'HOPOPT',
		1: 'ICMP',
		2: 'IGMP',
		3: 'GGP',
		4: 'IPv4',
		6: 'TCP',
		17: 'UDP',
		84: 'IPTM',
	}
	return protocol_names.get(protocol, 'Unknown')

def packet_analyse(header, data):
	eth_length = 14
	eth_header = data[:eth_length]
	eth = struct.unpack('! 6s 6s H', eth_header)
	src_mac = get_mac_address(eth[1])
	dest_mac = get_mac_address(eth[0])

	print('Source MAC: ', src_mac)
	print('Destination MAC: ', dest_mac)

	ip_header = data[eth_length:eth_length + 20]
	iph = struct.unpack('!BBHHHBBH4s4s', ip_header) # Extracted IP header in correct tuple format
	version_ihl = iph[0] # First byte of IPH is version of Internet Header Length
	ihl = version_ihl & 0xF # Last four bits are the Internet Header Length
	iph_length = ihl * 4
	src_ip = socket.inet_ntoa(iph[8]) # Making the source IP Address human readable
	dest_ip = socket.inet_ntoa(iph[9])
	protocol = iph[6] # Protocol extracted from IP Header tuple
	protocol_name = get_protocol_name(protocol)

	tcp_header = data[eth_length + iph_length:eth_length + iph_length + 20]
	dest_port = struct.unpack('!H', tcp_header[2:4])[0]
	#app_protocol = socket.getservbyport(dest_port)
    
	print('Source IP: ', src_ip)
	print('Destination IP: ', dest_ip)
	print('Protocol Value: ', str(protocol))
	print('Protocol: ', protocol_name)
	print('Application Protocol: ', dest_port)

	print('-------------------')

def packet_sniffer():
	sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	while True:
		rawdata, addr = sniffer.recvfrom(65536)
		packet_analyse(None, rawdata)

def get_mac_address(mac_bytes):
	mac_string = map('{:02x}'.format, mac_bytes)
	return ':'.join(mac_string)

filter_port()
open_port()
packet_sniffer()
