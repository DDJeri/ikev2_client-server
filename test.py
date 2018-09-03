# -*- coding: utf-8 -*-

import protocol
import payloads
from binascii import b2a_hex,a2b_hex
import socket
import threading
import os

local = ('192.167.136.1',500)
peer = ('192.167.137.1',500)
local_subnet = ('192.168.136.0','192.168.136.255')
peer_subnet = ('192.168.137.0','192.168.137.255')

peer_subnet_pool = {('192.167.137.1',500):('192.168.137.0','192.168.137.255'),
                    ('192.167.135.1',500):('192.168.135.0','192.168.135.255')}

UDPSock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
UDPSock.bind(('',500))

print 'i:initiator r:responder'
if raw_input() == 'i':
    ike = protocol.IKE(local,local_subnet,peer_subnet,peer)
    result = ike.init_send()
    UDPSock.sendto(result,peer)

    data,address = UDPSock.recvfrom(2048)
    if address != peer:
        raise Exception("Disabled")
    else:
        a = ike.parse_packet(data)
        ike.init_recv()
        b = ike.auth_send()
        UDPSock.sendto(b,peer)

    data,address = UDPSock.recvfrom(2048)
    if address != peer:
        raise Exception("Disabled")
    else:
        a = ike.parse_packet(data)
        ike.install_ipsec_sas()

else:
    # data,address = UDPSock.recvfrom(2048)
    # if address != peer:
    #     raise Exception("Disabled")
    # else:
    #     a = ike.parse_packet(data)
    #     ike.res_recv()
    #     result = ike.res_send()
    #     UDPSock.sendto(result,peer)

    # data,address = UDPSock.recvfrom(2048)
    # if address != peer:
    #     raise Exception("Disabled")
    # else:
    #     a = ike.parse_packet(data,flag = False)
    #     b = ike.auth_send(flag = False)
    #     UDPSock.sendto(b,peer)
    #     ike.install_ipsec_sas(flag = False)

    mutex = threading.Lock()
    client_pool = {}
    client_current = []   

    def Calculate_and_Send():
        global mutex , client_current , client_pool
        while True:
            if mutex.acquire():
                if len(client_current):
                    address , data = client_current.pop(0)

                    peer_sub = peer_subnet_pool[address]
                    if address not in client_pool:
                        ike = protocol.IKE(local,local_subnet,peer_sub,address)
                        ike.parse_packet(data)
                        ike.res_recv()
                        if UDPSock.sendto(ike.res_send(),address) > 0:
                            client_pool[address] = ike
                    else:
                        ike = client_pool[address]
                        if ike.state == 3: #INITR
                            ike.parse_packet(data,flag = False)
                            if UDPSock.sendto(ike.auth_send(flag = False),address) > 0:
                                ike.install_ipsec_sas(flag = False)
                                ike.state = 0
                mutex.release()

    def Receive():
        global mutex , client_current
        while True:
            data,address = UDPSock.recvfrom(2048)
            if mutex.acquire():
                client_current.append((address,data))
                mutex.release()

    if __name__ == "__main__":
        os.system('setkey -D -F')
        os.system('setkey -P -F')
        send_msg_thread = threading.Thread(target=Calculate_and_Send)
        send_msg_thread.start()
        Receive()
