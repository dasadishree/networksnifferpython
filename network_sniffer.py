import socket
import struct
import textwrap

# unpack ethernet frame (lowest level of data in network packet for the protocol)
def ethernet_frame(data):
    #unpack data (1st 14 bytes of ethernet frame into 2 6byte strings for MAC addresses and 1 2byte value)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()
