from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import socket
import struct
import subprocess

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
socketio = SocketIO(app)

packets = []
blocked_ports = []
opened_ports = []
blocked_addresses = {'source_ips': [], 'destination_ips': [], 'mac_addresses': []}
allowed_addresses = {'source_ips': [], 'destination_ips': [], 'mac_addresses': []}

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

    ip_header = data[eth_length:eth_length + 20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    protocol = iph[6]
    protocol_name = get_protocol_name(protocol)

    tcp_header = data[eth_length + iph_length:eth_length + iph_length + 20]
    dest_port = struct.unpack("!H", tcp_header[2:4])[0]

    if src_ip == '127.0.0.1' or dest_ip == '127.0.0.1':
        return

    packet = {
        'src_mac': src_mac,
        'dest_mac': dest_mac,
        'src_ip': src_ip,
        'dest_ip': dest_ip,
        'protocol': protocol,
        'protocol_name': protocol_name,
    }

    # Add packet to the list
    packets.append(packet)

    # Emit the new packet to all connected clients
    socketio.emit('new_packet', packet, namespace='/sniffer')

def packet_sniffer():
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        rawdata, addr = sniffer.recvfrom(65536)
        packet_analyse(None, rawdata)

def get_mac_address(mac_bytes):
    mac_string = map('{:02x}'.format, mac_bytes)
    return ':'.join(mac_string)

def get_iptables_rules():
    result = subprocess.run(['sudo', 'iptables', '-L'], capture_output=True, text=True)
    return result.stdout

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

@app.route('/')
def index():
    return render_template('ok1.html', )

@app.route('/portcontrol')
def portcontrol_page():
    return render_template('port_control.html', )

@app.route('/ipcontrol', methods=['GET'])
def ipcontrol_page():
    return render_template('ip_control.html', )

@app.route('/maccontrol', methods=['GET'])
def maccontrol_page():
    return render_template('mac_control.html', )

@app.route('/iptables')
def iptables():
    rules = get_iptables_rules()
    return render_template('iptables.html', rules = rules)

@app.route('/ns', methods=['POST'])
def nslookup():
    website = request.form['website']
    try:
        ip_address = socket.gethostbyname(website)
        return jsonify({'status': 'success', 'website': website, 'ip_address': ip_address})
    except socket.gaierror:
        return jsonify({'status': 'error', 'message': "Couldn't resolve the hostname."})

@app.route('/nslookup')
def nslookup_page():
    return render_template('nslookup.html')

# Port filter function

def filter_inport(port):
    command = ['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
    subprocess.run(command)
    blocked_ports.append(port)

def filter_outport(port):
    command = ['sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
    subprocess.run(command)
    blocked_ports.append(port)
    
@app.route('/block_port', methods=['POST'])
def block_port():
    inports = request.form.get('inports')
    outports = request.form.get('outports')
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
    
    if inports or outports:
        return jsonify({'message': 'Ports blocked successfully', 'blocked_ports': blocked_ports})
    else:
        return jsonify({'message': 'No ports blocked', 'blocked_ports': blocked_ports})

# Port open function

def open_inport(port):
    command = ['sudo', 'iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
    subprocess.run(command)
    opened_ports.append(port)

def open_outport(port):
    command = ['sudo', 'iptables', '-D', 'OUTPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
    subprocess.run(command)
    opened_ports.append(port)

@app.route('/open_port', methods=['POST'])
def open_port():
    # Code for opening port
    inports = request.form.get('inports')
    outports = request.form.get('outports')
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
    
    if inports or outports:
        return jsonify({'message': 'Ports opened successfully'})
    else:
        return jsonify({'message': 'No ports opened', 'opened_ports': opened_ports})

# IP Blocking

def block_source_ip(ip):
    command = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
    subprocess.run(command)
    blocked_addresses['source_ips'].append(ip)

def block_destination_ip(ip):
    command = ['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP']
    subprocess.run(command)
    blocked_addresses['destination_ips'].append(ip)
    
@app.route('/block_ip', methods=['POST'])
def block_ip():
    source_ips = request.form.get('source_ips')
    destination_ips = request.form.get('destination_ips')

    source_list = source_ips.split(' ')
    destination_list = destination_ips.split(' ')

    for source_ip in source_list:
        source_ip = source_ip.strip()
        if source_ip:
            block_source_ip(source_ip)
            print('The source IP address ', source_ip, ' has been blocked.\n')

    for destination_ip in destination_list:
        destination_ip = destination_ip.strip()
        if destination_ip:
            block_destination_ip(destination_ip)
            print('The destination IP address ', destination_ip, ' has been blocked.\n')

    if source_ips or destination_ips:
        return jsonify({'message': 'IP addresses blocked successfully', 'blocked_addresses': blocked_addresses})
    else:
        return jsonify({'message': 'No IP addresses blocked', 'blocked_addresses': blocked_addresses})
    

# IP Allow

def allow_source_ip(ip):
    command = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'ACCEPT']
    subprocess.run(command)
    allowed_addresses['source_ips'].append(ip)

def allow_destination_ip(ip):
    command = ['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'ACCEPT']
    subprocess.run(command)
    allowed_addresses['destination_ips'].append(ip)

@app.route('/allow_ip', methods=['POST'])
def allow_ip():
    # Code for allowing IP address
    source_ips = request.form.get('source_ips')
    destination_ips = request.form.get('destination_ips')

    source_list = source_ips.split(' ')
    destination_list = destination_ips.split(' ')

    for source_ip in source_list:
        source_ip = source_ip.strip()
        if source_ip:
            allow_source_ip(source_ip)
            print('The source IP address ', source_ip, ' has been allowed.\n')

    for destination_ip in destination_list:
        destination_ip = destination_ip.strip()
        if destination_ip:
            allow_destination_ip(destination_ip)
            print('The destination IP address ', destination_ip, ' has been allowed.\n')
    
    if source_ips or destination_ips:
        return jsonify({'message': 'IP addresses allowed successfully', 'allowed_addresses': allowed_addresses})
    else:
        return jsonify({'message': 'No IP addresses allowed'})


@socketio.on('connect', namespace='/sniffer')
def connect():
    # Send all existing packets to the connected client
    for packet in packets:
        socketio.emit('new_packet', packet, namespace='/sniffer')

if __name__ == '__main__':
    import threading
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.start()

    socketio.run(app, debug=True, port=8000)
