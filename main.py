import subprocess
import socket
import struct
import sys
from packetsniffer import packet_sniffer
import port as p
import ip

print('1. Block port')
print('2. Open port')
print('3. Block IP address')
print('4. Allow IP address')

option = input('Choose your action: ')

if option == '1':
	p.filter_port()
elif option == '2':
	p.open_port()
elif option == '3':
	ip.block_ip()
elif option == '4':
	ip.allow_ip()

sniff = str.upper(input('Would you like to start reading packets? Y or N\n'))

if sniff == 'Y':
	packet_sniffer()
else:
	sys.exit()
