import sys
from packetsniffer import packet_sniffer
import port as p
import ip
import mac

print('1. Block Port')
print('2. Open Port')
print('3. Block IP Address')
print('4. Allow IP Address')
print('5. MAC Address Control')

option = input('Choose your action: ')

if option == '1':
	p.filter_port()
elif option == '2':
	p.open_port()
elif option == '3':
	ip.block_ip()
elif option == '4':
	ip.allow_ip()
elif option == '5':
	mac.mac()

sniff = str.upper(input('Would you like to start reading packets? Y or N\n'))

if sniff == 'Y':
	packet_sniffer()
else:
	sys.exit()
