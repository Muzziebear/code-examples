# Python script to scan the host computer's subnet and return 
# IP addresses of computers connected (assumes /24 subnet)
# Resources used: "Black Hat Python" by Justin Seitz


import socket
import os
import struct
from ctypes import *
import threading
import time
from netaddr import IPNetwork, IPAddress


# IP header
class IP(Structure):
	_fields_ = 
	[
		("ihl", c_ubyte, 4),
		("version", c_ubyte, 4),
		("tos", c_ubyte),
		("len", c_ushort),
		("id", c_ushort),
		("offset", c_ushort),
		("ttl", c_ubyte),
		("protocol_num", c_ubyte),
		("sum", c_ushort),
		("src", c_uint32),
		("dst", c_uint32)
	]

	def __new__(self, socket_buffer=None):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer=None):
		# map protocol constants to their names
		self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

		# human readable IP addresses
		self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
		self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

		# human readable protocol
		try:
			self.protocol = self.protocol_map[self.protocol_num]
		except:
			self.protocol = str(self.protocol_num)


class ICMP(Structure):
	_fields_ = 
	[
		("type", c_ubyte),
		("code", c_ubyte),
		("checksum", c_ushort),
		("unused", c_ushort),
		("next_hop_mtu", c_ushort)
	]

	def __new__(self, socket_buffer):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer):
		pass



def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

# send the UDP datagrams
def udp_sender(subnet, magic_message):
	time.sleep(5)
	sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	for ip in IPNetwork(subnet):
		try:
			sender.sendto(magic_message, ("%s" % ip,65212))
		except:
			pass

def main():
	# host to listen on
	host = get_ip_address()

	# subnet to target
	subnet = host.split(".")
	subnet = ".".join(subnet[0:3]) + ".0/24"

	# magic string we'll check ICMP response for
	magic_message = "PYTHONRULES!"

	# start sending packets
	udp_thread = threading.Thread(target=udp_sender, args=(subnet, magic_message))
	udp_thread.start()

	if os.name == "nt":
		windows = True
	else:
		windows = False

	if windows:
		socket_protocol = socket.IPPROTO_IP
	else:
		socket_protocol = socket.IPPROTO_ICMP

	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

	sniffer.bind((host, 0))
	print "Listening on %s" % host
	sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	if windows:
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

	try:
		while True:
			# read in a packet
			raw_buffer = sniffer.recvfrom(65565)[0]

			# create an IP header from the first 20 bytes of the buffer
			ip_header = IP(raw_buffer[0:20])
			# print out the protocol that was detected and the hosts
			# print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)

			if ip_header.protocol == "ICMP":
				# calculate where our ICMP packet starts
				offset = ip_header.ihl * 4
				buf = raw_buffer[offset:offset + sizeof(ICMP)]

				# create our ICMP structure
				icmp_header = ICMP(buf)

				# print ICMP Type and Code
				# print "ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code)

				# check for Type 3 (Destination Unreachable) and Code 3 (Port Unreachable)
				if icmp_header.code == 3 and icmp_header.type == 3:
					# make sure host is in our target subnet
					if IPAddress(ip_header.src_address) in IPNetwork(subnet) and raw_buffer[len(raw_buffer) - len(magic_message):] == magic_message:
						print "Host Up: %s" % ip_header.src_address


	except Exception, e:
		# if we're using Windows, turn off promiscuous mode
		print e
		if windows:
			sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == '__main__':
	main()
