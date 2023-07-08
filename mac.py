#Use this as template

import subprocess

def allow_mac_address(mac_address):
	command = ['sudo', 'iptables', '-A', 'INPUT', '-m', 'mac', '--mac-source', mac_address, '-j', 'ACCEPT']
	subprocess.run(command)

def block_mac_address(mac_address):
	command = ['sudo', 'iptables', '-A', 'INPUT', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP']
	subprocess.run(command)

def mac():
	mac_address = input('Enter the MAC address to allow/block: ')
	action = str.lower(input("Enter 'allow' to allow or 'block' to block: "))
	
	if mac_address:
		if action == 'allow':
		    allow_mac_address(mac_address)
		    print('The MAC address ', mac_address, ' has been allowed.')
		elif action == 'block':
		    block_mac_address(mac_address)
		    print('The MAC address ', mac_address, ' has been blocked.')
		else:
		    print("Invalid action. Please enter 'allow' or 'block'.")
