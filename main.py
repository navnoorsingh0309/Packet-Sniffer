import socket, struct

#creating a socket
#AF_PACKET: socket which allows to send and receive raw packets thorugh kernel(works only on linux)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

#Till Infinite
while True:
    #Receiving all the data (max 2^16=65536)
    data, addr = s.recvfrom(65535)
    #as per the frame of packet
    #Frame
    #Destination Address(6bytes)   Source Address(6bytes)   Ethernet_Protocol(2 Bytes) [14 bytes]    
    Dest_mac_bytes, Source_mac_bytes, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    Dest_mac = ':'.join(map('{:02x}'.format, Dest_mac_bytes)).upper()
    Source_mac = ':'.join(map('{:02x}'.format, Source_mac_bytes)).upper()
    #Version(0.5 byte)    Header_length(0.5 byte)   Total_length(2bytes)   Identifier(2bytes)   Flags(3 bits)   Fragment_offset(13 bits)
    #TTL(Time to Live)(1 byte) Protocol(1 byte)  Header_Checksum(2 byte)  Source_IP(4 bytes)   Dest_IP(4 bytes)
    #Unit of Header length is 32-bit like for 20 byte(minimum) header, we will see a 5 and for
    #24byte(maximum), we will see a 6 
    #we have an options field after dest_IP which includes in header and results above observation but this is generally not used
    #After this data comes.
    version_head, Type_of_service, Total_length, Identifier, Flags_Fragment_offset, TTL, Protocol, Header_checksum, Source_addr, Dest_addr = struct.unpack('! B B H H H B B H 4s 4s', data[14:34])
    #bitwise shifting 4 bits
    version = version_head >> 4
    #TO get alst 4 bits
    heading_length = version_head & 15
    #If no data is transferring or receving
    if '.'.join(map(str, Source_addr))!='127.0.0.1':
        print('Message is sent from {} to {}'.format('.'.join(map(str, Source_addr)), '.'.join(map(str, Dest_addr))))
        print('Mac Address is sent from {} to {} with Protocol {}'.format(Source_mac ,Dest_mac, socket.ntohs(eth_proto)))
        print('Message version is {} and Header Length is {}'.format(version, heading_length))
        print('Total Length of Message is {}'.format(Total_length))
        print('Identifier is {}'.format(Identifier))
        #Finding x_bit, Do not Fragment Flag, More Fragments Follow Flag
        x_bit = (Flags_Fragment_offset >> 15) & 1
        DFFlag = (Flags_Fragment_offset >> 14) & 1
        MFFFlag = (Flags_Fragment_offset >> 13) & 1
        Fragment_Offset = Flags_Fragment_offset & 8191
        print('xbit is {} , Do not Fragment Flag is {}  , More Fragments Follow Flag is {} and Fragement Offset is {}'.format(x_bit, DFFlag, MFFFlag, Fragment_Offset))
        print('TTL is {} , Protocol is {} and Header Checksum is {}\n'.format(TTL, Protocol, Header_checksum))
        
