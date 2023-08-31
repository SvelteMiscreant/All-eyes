from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import socket
import struct
import mysql.connector
import json
import threading

app = Flask(__name__)
#app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)

# MySQL database configuration
'''db = mysql.connector.connect(
    host='localhost',
    user='alleyes',
    password='mudrakali',
    database='packets')
cursor = db.cursor()'''


packets = []
#capture_active = False

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
    #app_protocol = socket.getservbyport(dest_port)

    packets.append({
        'src_mac': src_mac,
        'dest_mac': dest_mac,
        'src_ip': src_ip,
        'dest_ip': dest_ip,
        'protocol': protocol,
        'protocol_name': protocol_name,
        #'app_protocol': app_protocol
    })
    
# Insert the packet information into the MySQL database
    #insert_query = "INSERT INTO packet_data (src_mac, dest_mac, src_ip, dest_ip, protocol, protocol_name) VALUES (%s, %s, %s, %s, %s, %s)"
    #values = (src_mac, dest_mac, src_ip, dest_ip, protocol, protocol_name)
    #cursor.execute(insert_query, values)
    #db.commit()

def packet_sniffer():
    #global capture_active
	sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    #while capture_active:
	rawdata, addr = sniffer.recvfrom(65536)
	packet_analyse(None, rawdata)
        
#@socketio.on('start_capture')
#def start_capture():
    #global capture_active

    #if not capture_active:
        #capture_active = True
        #sniffer_thread = threading.Thread(target=packet_sniffer)
        #sniffer_thread.start()
        
#@socketio.on('stop_capture')
#def stop_capture():
    #global capture_active
    #capture_active = False
 
def get_mac_address(mac_bytes):
	mac_string = map('{:02x}'.format, mac_bytes)
	return ':'.join(mac_string)


@app.route('/')
def index():
    return render_template('index.html')

'''@socketio.on('connect')
def handle_connect():
    # Retrieve packet data from the MySQL database
    select_query = "SELECT * FROM packet_data"
    cursor.execute(select_query)
    packets = cursor.fetchall()

    # Convert packet data to JSON
    packet_list = []
    for packet in packets:
        packet_dict = {
            'src_mac': packet[0],
            'dest_mac': packet[1],
            'src_ip': packet[2],
            'dest_ip': packet[3],
            'protocol': packet[4],
            'protocol_name': packet[5]
        }
        packet_list.append(packet_dict)

    json_data = json.dumps(packet_list)

    # Emit JSON data to the client
    emit('packet_data', json_data)
    
    # Print the JSON data
    #print(json_data)

if __name__ == '__main__':
    socketio.run(app, debug=True)'''


if __name__ == '__main__':
    import threading
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.start()

    app.run(debug=True)
