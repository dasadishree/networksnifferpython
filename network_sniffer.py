import socket
import struct
import textwrap

# unpack ethernet frame (lowest level of data in network packet for the protocol)
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# function to format mac addresses to readable format
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# unpack IPv4 layer
def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# format IP addresses 
def ipv4(addr):
    return '.'.join(map(str, addr))

# unpack ICMP packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# unpack TCP packets
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, data[offset:]

# unpack UDP packets
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# format readable output
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ' '.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# create raw socket
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# loop to capture and process packets
while True:
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    print('\nEthernet Frame:')
    print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

    # IPv4
    if eth_proto == 8:
        (ttl, proto, src, target, data) = ipv4_packet(data)
        print('\t- IPv4 Packet:')
        print(f'\t\t- Source: {src}, Target: {target}, TTL: {ttl}')

        # ICMP
        if proto == 1:
            icmp_type, code, checksum, data = icmp_packet(data)
            print('\t- ICMP Packet:')
            print(f'\t\t- Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
            print(f'\t\t- Data: {format_multi_line("\t\t\t", data)}')

        # TCP
        elif proto == 6:
            src_port, dest_port, sequence, acknowledgment, data = tcp_segment(data)
            print('\t- TCP Segment:')
            print(f'\t\t- Source Port: {src_port}, Destination Port: {dest_port}')
            print(f'\t\t- Sequence: {sequence}, Acknowledgment: {acknowledgment}')
            # Simply use the tab character directly
            print(f'\t\t- Data: {format_multi_line("\t\t\t", data)}')

        # UDP
        elif proto == 17:
            src_port, dest_port, length, data = udp_segment(data)
            print('\t- UDP Segment:')
            print(f'\t\t- Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
