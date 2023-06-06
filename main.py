import struct
import socket
import binascii

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0800))
while True:
  packet = s.recvfrom(2048)

ethernet_header = packet[0][0:14]
eth_header = struct.unpack("!6s6s2s", ethernet_header)

print("Destination MAC:" + binascii.hexlify(eth_header[0]) + " Source MAC:" + binascii.hexlify(eth_header[1]) + " Type:" + binascii.hexlify(eth_header[2]))
