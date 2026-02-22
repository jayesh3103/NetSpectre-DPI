import struct

def write_pcap(filename):
    with open(filename, 'wb') as f:
        # PCAP Global Header
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        
        # Helper to write packet
        def write_packet(data):
            f.write(struct.pack('<IIII', 0, 0, len(data), len(data)))
            f.write(data)
            
        # Dummy Ethernet + IP + TCP + payload
        pkt1 = b'\x00' * 14 + b'\x45\x00\x00\x28' + b'\x00' * 16 + b'\x11\x22\x01\xbb' + b'\x00'*16 + b'\x16\x03\x01\x00\x00'
        write_packet(pkt1)
        
write_pcap('test_dpi.pcap')
print('test_dpi.pcap created')
