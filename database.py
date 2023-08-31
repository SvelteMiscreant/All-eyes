import mysql.connector

# Connect to the MySQL server
cnx = mysql.connector.connect(
    host='localhost',
    user='alleyes',
    password='mudrakali',
    database='packets'
)

# Create a cursor object to execute SQL queries
cursor = cnx.cursor()

# Insert a new packet into the table
insert_query = """
INSERT INTO packet_data (src_mac, dest_mac, src_ip, dest_ip, protocol, protocol_name)
VALUES (%s, %s, %s, %s, %s, %s)
"""
packet_data = ('00:11:22:33:44:55', 'AA:BB:CC:DD:EE:FF', '192.168.1.100', '192.168.1.200', 'TCP', 'HTTP')
cursor.execute(insert_query, packet_data)
cnx.commit()

# Fetch all packets from the table
select_query = "SELECT * FROM packet_data"
cursor.execute(select_query)
packets = cursor.fetchall()

for packet in packets:
    print(packet)

# Close the cursor and connection
cursor.close()
cnx.close()


<!DOCTYPE html>
<html>
<head>
    <title>Packet Sniffer</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }

        h1 {
            margin: 0;
            padding: 20px;
        }

        #scrollableBox {
            flex: 1;
            overflow: auto;
            padding: 20px;
            position: relative;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid black;
        }

        th, td {
            padding: 8px;
            border: 1px solid black;
            width: fit-content;
    	    padding: 14px 35px;
        }

        thead {
            position: sticky;
            top: 0;
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <h1>Packet Sniffer</h1>
    <div id="scrollableBox">
        <table id="packetTable">
            <thead>
                <tr>
                    <th>Source MAC</th>
                    <th>Destination MAC</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Protocol</th>
                    <th>Protocol Name</th>
                </tr>
            </thead>
            <tbody>
                {% for packet in packets %}
                <tr>
                    <td>{{ packet.src_mac }}</td>
                    <td>{{ packet.dest_mac }}</td>
                    <td>{{ packet.src_ip }}</td>
                    <td>{{ packet.dest_ip }}</td>
                    <td>{{ packet.protocol }}</td>
                    <td>{{ packet.protocol_name }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>


/////////////////////////////////////


<!DOCTYPE html>
<html>
<head>
    <title>Packet Sniffer</title>
    <style>
        #packet-table {
            width: 100%;
            border-collapse: collapse;
        }

        #packet-table th,
        #packet-table td {
            padding: 8px;
            border: 1px solid #ccc;
        }

        #packet-table th {
            background-color: #f2f2f2;
        }

        #packet-table tbody {
            display: block;
            height: 300px;
            overflow-y: scroll;
        }

        #packet-table thead,
        #packet-table tbody tr {
            display: table;
            width: 100%;
            table-layout: fixed;
        }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.3.2/socket.io.js"></script>
</head>
<body>
    <h1>Packet Sniffer</h1>
    <table id="packet-table">
        <thead>
            <tr>
                <th>Source MAC</th>
                <th>Destination MAC</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Protocol Name</th>
            </tr>
        </thead>
        <tbody id="packet-list"></tbody>
    </table>

    <script>
        // Connect to the WebSocket server
        const socket = io();

        // Receive packet data from the server
        socket.on('packet_data', function(jsonData) {
            const packets = JSON.parse(jsonData);

            // Update the packet table on the webpage
            const packetList = document.getElementById('packet-list');
            packetList.innerHTML = '';

            packets.forEach(function(packet) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${packet.src_mac}</td>
                    <td>${packet.dest_mac}</td>
                    <td>${packet.src_ip}</td>
                    <td>${packet.dest_ip}</td>
                    <td>${packet.protocol}</td>
                    <td>${packet.protocol_name}</td>
                `;
                packetList.appendChild(row);
            });
        });
    </script>
</body>
</html>
