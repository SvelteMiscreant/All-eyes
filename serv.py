from flask import Flask, render_template
from flask_socketio import SocketIO
import socket
import struct

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
socketio = SocketIO(app)

packets = []

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

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect', namespace='/sniffer')
def connect():
    # Send all existing packets to the connected client
    for packet in packets:
        socketio.emit('new_packet', packet, namespace='/sniffer')

if __name__ == '__main__':
    import threading
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.start()

    socketio.run(app, debug=True)
