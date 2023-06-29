import subprocess

# IP Blocking

def block_source_ip(ip):
	command = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
	subprocess.run(command)
    
def block_destination_ip(ip):
	command = ['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP']
	subprocess.run(command)

def block_ip():
	source_ips = input('Enter the source IP addresses to block, separate by spaces: ')
	destination_ips = input('Enter the destination IP addresses to block, separate by spaces: ')

	source_list = source_ips.split(' ')
	destination_list = destination_ips.split(' ')

	for source_ip in source_list:
		source_ip = source_ip.strip()
		if source_ip:
			block_source_ip(source_ip)
			print('The source IP address, ' source_ip, ' has been blocked.\n')
			
	for destination_ip in destination_list:
		destination_ip = destination_ip.strip()
		if destination_ip:
			block_destination_ip(destination_ip)
			print('The destination IP address, ' destination_ip, ' has been blocked.\n')

# IP Allow

def allow_source_ip(ip):
	command = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'ACCEPT']
	subprocess.run(command)
	
def allow_destination_ip(ip):
	command = ['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'ACCEPT']
	subprocess.run(command)
	
def allow_ip():
	source_ips = input('Enter the source IP addresses to allow, separate by spaces: ')
	destination_ips = input('Enter the destination IP addresses to allow, separate by spaces: ')

	source_list = source_ips.split(' ')
	destination_list = destination_ips.split(' ')

	for source_ip in source_list:
		source_ip = source_ip.strip()
		if source_ip:
			allow_source_ip(source_ip)
			print('The source IP address, ' source_ip, ' has been allowed.\n')
			
	for destination_ip in destination_list:
		destination_ip = destination_ip.strip()
		if destination_ip:
			allow_destination_ip(destination_ip)
			print('The destination IP address, ' destination_ip, ' has been allowed.\n')
