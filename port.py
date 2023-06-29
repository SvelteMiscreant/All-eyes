import subprocess
 
def validate_port(port):
	if not port:
		return None
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
	command = ['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
	subprocess.run(command)
	
def filter_outport(port):
	command = ['sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
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
	command = ['sudo', 'iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
	subprocess.run(command)
	
def open_outport(port):
	command = ['sudo', 'iptables', '-D', 'OUTPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
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
