# -*- coding: utf-8 -*-

import protocol
import payloads
from binascii import b2a_hex,a2b_hex
import socket
from Crypto.Util.number import long_to_bytes, bytes_to_long


src = ('192.167.136.1',500)
dst = ('192.167.137.1',500)

src_subnet = ('192.168.136.0','192.168.136.255')
dst_subnet = ('192.168.137.0','192.168.137.255')

UDPSock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
#UDPSock.bind(('',500))
ike = protocol.IKE(src,src_subnet,dst_subnet,peer = dst)

print 'i:initiator r:responder'
if raw_input() == 'i':
    result = ike.init_send()
    UDPSock.sendto(result,dst)

    data,address = UDPSock.recvfrom(2048)
    if address != dst:
        raise Exception("Disabled")
    else:
        a = ike.parse_packet(data)
        ike.init_recv()
        b = ike.auth_send()
        UDPSock.sendto(b,dst)

    data,address = UDPSock.recvfrom(2048)
    if address != dst:
        raise Exception("Disabled")
    else:
        a = ike.parse_packet(data)
        ike.install_ipsec_sas()

else:
    data,address = UDPSock.recvfrom(2048)
    if address != dst:
        raise Exception("Disabled")
    else:
        a = ike.parse_packet(data)
        ike.res_recv()
        result = ike.res_send()
        UDPSock.sendto(result,dst)

    data,address = UDPSock.recvfrom(2048)
    if address != dst:
        raise Exception("Disabled")
    else:
        a = ike.parse_packet(data,flag = False)
        b = ike.auth_send(flag = False)
        UDPSock.sendto(b,dst)
        ike.install_ipsec_sas(flag = False)

