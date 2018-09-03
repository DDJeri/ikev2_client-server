# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko.
#

"""
High level interface to `IKEv2 protocol <http://tools.ietf.org/html/draft-kivinen-ipsecme-ikev2-rfc5996bis-02>`_
"""
from enum import IntEnum
from functools import reduce
from hmac import HMAC
import logging
import operator
import os
import hmac
from hashlib import sha256,sha1
from struct import unpack
import binascii
import struct
from math import ceil

from auth import pubkey_verify,priv_sign
from prf import prfplus
import payloads
import const
import proposal
from prf_hamc_sha256 import key_generator
import AES128
import payloads
import sys
sys.path.append('./pyDHE/')
import DH


SPDADD_SYNTAX = """
spdadd {mysubip}/24 {peersubip}/24 any -P out ipsec\n\tesp/tunnel/{myip}-{peerip}/require;
spdadd {peersubip}/24 {mysubip}/24 any -P in ipsec\n\tesp/tunnel/{peerip}-{myip}/require;
"""
ESP_ADD_SYNTAX = 'add {ip_from} {ip_to} esp 0x{spi} -m tunnel\n\t-E aes-cbc 0x{key_e}\n\t-A hmac-sha1 0x{key_a};'

MACLEN = 16

logger = logging.getLogger(__name__)


class State(IntEnum):
    STARTING = 0
    INIT = 1
    AUTH = 2
    INITR = 3
    AUTHR = 4


class IkeError(Exception):
    pass


class IKE(object):
    """
    A single IKE negotiation / SA.

    Currently implements only Initiator side of the negotiation.
    """
    def __init__(self, address, left = None,right = None,peer = None, dh_group=14, nonce_len=32):
        """

        :param address: local address tuple(host, port)
        :param peer: remote address tuple(host, port)
        :param dh_group: diffie hellman group number
        :param nonce_len: length of Nonce data
        """
        self.iSPI = 0  # XXX: Should be generated here and passed downwards
        self.rSPI = 0
        self.left = left
        self.right = right
        self.diffie_hellman = dh_group           # dh_group = 14
        self.N = os.urandom(nonce_len)
        self.packets = list()
        self.state = State.STARTING
        self.address = address
        self.peer = peer
        self.dh = DH.DHE()

    def init_send(self):
        """
        Generates the first (IKE_INIT) packet for Initiator

        :return: bytes() containing a valid IKE_INIT packet
        """
        packet = Packet()
        packet.add_payload(payloads.SA())
        packet.add_payload(payloads.KE(diffie_hellman=self.diffie_hellman,key = self.dh.getPublicKey()))
        packet.add_payload(payloads.Nonce(nonce=self.N))
        packet.iSPI = self.iSPI = packet.payloads[0].spi
        self.state = State.INIT
        self.packets.append(packet)
        return packet.__bytes__()

    def init_recv(self):
        """
        Parses the IKE_INIT response packet received from Responder.

        Assigns the correct values of rSPI and Nr
        Calculates Diffie-Hellman exchange and assigns all keys to self.

        """
        assert len(self.packets) == 2
        packet = self.packets[-1]
        for p in packet.payloads:
            if p._type == payloads.Type.Nonce:
                self.Nr = p._data
                logger.debug(u"Responder nonce {}".format(binascii.hexlify(self.Nr)))
            elif p._type == payloads.Type.KE:
                self.shared_secret = self.dh.update(p.kex_data)
            else:
                logger.debug('Ignoring: {}'.format(p))

        logger.debug('Nonce I: {}\nNonce R: {}'.format(binascii.hexlify(self.N), binascii.hexlify(self.Nr)))

        keymat = key_generator(self.N , self.Nr , self.shared_secret , SPIi = struct.pack('!Q',self.iSPI), SPIr = struct.pack('!Q',self.rSPI)) #,   #计算SKEYSEED(字节流)(接口)


        logger.debug("Got %d bytes of key material" % len(keymat))
        # get keys from material
        ( self.SK_d,
          self.SK_ai,
          self.SK_ar,
          self.SK_ei,
          self.SK_er,
          self.SK_pi,
          self.SK_pr ) = unpack("32s32s32s16s16s32s32s", keymat[0:192])  # XXX: Should support other than 256-bit algorithms, really.

    def res_recv(self):
        packet = self.packets[-1]
        self.iSPI = packet.iSPI
        for p in packet.payloads:
            if p._type == payloads.Type.Nonce:
                self.Ni = p._data
                logger.debug(u"Responder nonce {}".format(binascii.hexlify(self.Ni)))
            elif p._type == payloads.Type.KE:
                 self.key_init = p.kex_data
            else:
                logger.debug('Ignoring: {}'.format(p))

    def res_send(self):
        packet = Packet(iSPI=self.iSPI,flag = False)
        packet.add_payload(payloads.SA())
        packet.add_payload(payloads.KE(diffie_hellman=self.diffie_hellman,key = self.dh.getPublicKey()))
        packet.add_payload(payloads.Nonce(nonce=self.N))

        packet.rSPI = self.rSPI = packet.payloads[0].spi
        #packet.add_payload(payloads.Notify(notify_type = const.MessageType.NAT_DETECTION_SOURCE_IP,notify_data = struct.pack("!2Q",self.iSPI,self.rSPI) + self.address[0]))
        #packet.add_payload(payloads.Notify(notify_type = const.MessageType.NAT_DETECTION_DESTINATION_IP,notify_data = struct.pack("!2Q",self.iSPI,self.rSPI) + self.peer[0]))
        
        cakeyinfo = open('../ca.der').read()
        cakeyinfo = cakeyinfo[195:195+162]
        hashinfo = sha1(cakeyinfo).hexdigest()
        packet.add_payload(payloads.CERTREQ(auth_data = binascii.a2b_hex(hashinfo)))

        packet.add_payload(payloads.Notify(notify_type = const.MessageType.SIGNATURE_HASH_ALGORITHMS,notify_data = binascii.a2b_hex("0001000200030004")))

        #packet.rSPI = self.rSPI = packet.payloads[0].spi
        self.shared_secret = self.dh.update(self.key_init)
        keymat = key_generator(self.Ni , self.N , self.shared_secret , SPIi = struct.pack('!Q',self.iSPI), SPIr = struct.pack('!Q',self.rSPI)) #,   #计算SKEYSEED(字节流)(接口)
        logger.debug("Got %d bytes of key material" % len(keymat))
        ( self.SK_d,
          self.SK_ai,
          self.SK_ar,
          self.SK_ei,
          self.SK_er,
          self.SK_pi,
          self.SK_pr ) = unpack("32s32s32s16s16s32s32s", keymat[0:192])  # XXX: Should support other than 256-bit algorithms, really.

        self.packets.append(packet)
        self.state = State.INITR
        return packet.__bytes__()


    def auth_send(self,flag = True):           #flag = true: initiator        flag = flase: responder
        """
        Generates the second (IKE_AUTH) packet for Initiator

        :return: bytes() containing a valid IKE_INIT packet
        """
        #assert len(self.packets) == 2
        packet = Packet(exchange_type=const.ExchangeType.IKE_AUTH, iSPI=self.iSPI, rSPI=self.rSPI,flag = flag)

        if flag:
            # Add IDi (35)
            id_payload = payloads.IDi()
            packet.add_payload(id_payload)
            
            # Add AUTH (39)
            #signed_octets = bytes(self.packets[0]) + self.Nr + prf(self.SK_pi, id_payload._data)
            ikedata = self.packets[0].__bytes__()
            signed_octets = ikedata + self.Nr + self.SK_pi + id_payload._data
            packet.add_payload(payloads.AUTH(signed_octets,length = len(ikedata)))
            #print b2a_hex(packet.payloads[-1].__bytes__())

            # Add SA (33)
            self.esp_SPIin = os.urandom(4)
            packet.add_payload(payloads.SA(proposals=[
                proposal.Proposal(protocol=const.ProtocolID.ESP, spi=self.esp_SPIin, last=True, transforms=[
                    ('ENCR_AES_CBC', 128), ('ESN',), ('AUTH_HMAC_SHA1_96',)
                ])
            ]))
            #print b2a_hex(packet.payloads[-1].__bytes__())

            #接口
            cakeyinfo = open('../ca.der').read()
            cakeyinfo = cakeyinfo[195:195+162]
            hashinfo = sha1(cakeyinfo).hexdigest()
            packet.add_payload(payloads.CERTREQ(auth_data = binascii.a2b_hex(hashinfo)))
            
            #接口
            packet.add_payload(payloads.CERT(cert_data = open('../server.der').read()))
            # Add TSi (44)
            leftaddress = self.left[0]
            leftaddress = leftaddress.split('.')
            left = int(leftaddress[0])*256**3 + int(leftaddress[1])*256**2 + int(leftaddress[2])*256**1 + int(leftaddress[3])*256**0
            packet.add_payload(payloads.TSi(lsubnet = left, rsubnet = left + 255))

            # Add TSr (45)
            rightaddress = self.right[0]
            rightaddress = rightaddress.split('.')
            right = int(rightaddress[0])*256**3 + int(rightaddress[1])*256**2 + int(rightaddress[2])*256**1 + int(rightaddress[3])*256**0
            packet.add_payload(payloads.TSr(lsubnet = right, rsubnet = right + 255))

            # Add N(INITIAL_CONTACT)
            packet.add_payload(payloads.Notify(notify_type=const.MessageType.INITIAL_CONTACT))

            self.packets.append(packet)

            nopadding = packet.__bytes__()      ##########
            #print b2a_hex(nopadding),len(nopadding)
        else:
            # Add IDr (36)
            id_payload = payloads.IDr()
            packet.add_payload(id_payload)

            # Add AUTH (39)
            #signed_octets = bytes(self.packets[0]) + self.Nr + prf(self.SK_pi, id_payload._data)
            ikedata = self.packets[1].__bytes__()
            signed_octets = ikedata + self.Ni + self.SK_pr + id_payload._data
            packet.add_payload(payloads.AUTH(signed_octets,length = len(ikedata)))

            self.esp_SPIin = os.urandom(4)
            packet.add_payload(payloads.SA(proposals=[
                proposal.Proposal(protocol=const.ProtocolID.ESP, spi=self.esp_SPIin, last=True, transforms=[
                    ('ENCR_AES_CBC', 128), ('ESN',), ('AUTH_HMAC_SHA1_96',)
                ])
            ]))

            packet.add_payload(payloads.CERT(cert_data = open('../server.der').read()))
            # Add TSi (44)
            rightaddress = self.right[0]
            rightaddress = rightaddress.split('.')
            right = int(rightaddress[0])*256**3 + int(rightaddress[1])*256**2 + int(rightaddress[2])*256**1 + int(rightaddress[3])*256**0
            packet.add_payload(payloads.TSi(lsubnet = right, rsubnet = right + 255))

            # Add TSr (45)
            leftaddress = self.left[0]
            leftaddress = leftaddress.split('.')
            left = int(leftaddress[0])*256**3 + int(leftaddress[1])*256**2 + int(leftaddress[2])*256**1 + int(leftaddress[3])*256**0
            packet.add_payload(payloads.TSr(lsubnet = left, rsubnet = left + 255))

            # Add N(INITIAL_CONTACT)
            packet.add_payload(payloads.Notify(notify_type=const.MessageType.INITIAL_CONTACT))

            self.packets.append(packet)

            nopadding = packet.__bytes__()      ##########

        a = int(ceil((len(nopadding)-28)  / 16.0))
        b = a*16 - (len(nopadding) - 28)
        if b > 0:
            padding = nopadding + b'\x01' * (b-1) + struct.pack('!B',b-1)
        else:
            padding = nopadding
        self.state = State.AUTH

        iv = os.urandom(16)
        if flag:
            ciphertext = AES128.encrypt(iv,self.SK_ei,padding)
        else:
            ciphertext = AES128.encrypt(iv,self.SK_er,padding)

        final = Packet(exchange_type=packet.exchange_type, iSPI=packet.iSPI, rSPI=packet.rSPI, message_id=1,flag=flag)
        sk = payloads.SK(next_payload=packet.payloads[0]._type, iv=iv, ciphertext=ciphertext)
        final.add_payload(sk)
        data = final.__bytes__()
        if flag:
            sign = AES128.hash256(iv,self.SK_ai,data)
        else:
            sign = AES128.hash256(iv,self.SK_ar,data)
        data = data[:-16] + sign[:16]
        return data
    
    def auth_verify(self, data,flag = True):            #flag = true: initiator        flag = flase: responder
        if flag:
            sign = AES128.hash256("0000000000000000",self.SK_ar,data)
        else:
            sign = AES128.hash256("0000000000000000",self.SK_ai,data)
        hash_data = data[len(data)-16 : len(data)]
        if hash_data != sign[:16]:
            raise IkeError("Hash_verify Failed!")
        else:
            print "Integrity verify successfully!"
            iv = data[const.IKE_HEADER.size + 4 : const.IKE_HEADER.size + 4 + 16]
            if flag:
                data2 = AES128.decrypt_hash(iv,self.SK_er,data[const.IKE_HEADER.size + 4 + 16:-16])
            else:
                data2 = AES128.decrypt_hash(iv,self.SK_ei,data[const.IKE_HEADER.size + 4 + 16:-16])
            #return data[:const.IKE_HEADER.size + 4 + 16] + data2 + data[len(data) - 16 : len(data)]
            next_type = struct.unpack("!B",data[const.IKE_HEADER.size])
            return next_type[0] , data2

    def sign_verify(self,flag = True):#flag = true: initiator        flag = flase: responder
        packet = self.packets[-1]
        t = 0
        while packet.payloads[t].next_payload:
            payload = packet.payloads[t]
            if payload._type == 35 or payload._type == 36:
                id_payload = payload._data
            if payload._type == 37:
                buffer = payload._data
            if payload._type == 39:
                data = payload._data
                if data[0] == binascii.a2b_hex("01"):
                    sha = 'sha1'
                else:
                    sha = 'sha256'
                sign = data[len(data) - 128 : len(data)]
            t += 1
        
        if flag:
            Realmessage = self.packets[1]
            nonce = self.N
            MACedID = binascii.a2b_hex(hmac.new(self.SK_pr, id_payload, digestmod=sha256).hexdigest())
        else:
            Realmessage = self.packets[0]
            nonce = self.N
            MACedID =binascii.a2b_hex(hmac.new(self.SK_pi, id_payload, digestmod=sha256).hexdigest())

        InitiatorSignedOctets = Realmessage.__bytes__() + nonce + MACedID
        pubkey_verify(buffer[1:len(buffer)],sign,InitiatorSignedOctets,sha)

    def parse_packet(self, data,flag = True):
        """
        Parses a received packet in to Packet() with corresponding payloads.
        Will decrypt encrypted packets when needed.

        :param data: bytes() IKE packet from wire.
        :return: Packet() instance
        :raise IkeError: on malformed packet
        """
        verify_flag = False
        if self.iSPI != 0:
            j = 0
            t = struct.pack("!Q",self.iSPI)
            while(data[j] != t[0]):
                j += 1
            data = data[j:len(data)]
        else:
            data = data

        packet = Packet(data=data)
        packet.header = data[0:const.IKE_HEADER.size]
        (packet.iSPI, packet.rSPI, next_payload, packet.version, exchange_type, packet.flags,
         packet.message_id, packet.length) = const.IKE_HEADER.unpack(packet.header)
        packet.exchange_type = const.ExchangeType(exchange_type)

        self.rSPI = packet.rSPI

        logger.debug("next payload: {!r}".format(next_payload))
        
        if next_payload == 46:             # hash验证和解码(接口)
            next_payload , data = self.auth_verify(data,flag = flag)
            verify_flag = True
            #print binascii.b2a_hex(data)
        else:
            data = data[const.IKE_HEADER.size:]

        while next_payload:
            logger.debug('Next payload: {0!r}'.format(next_payload))
            logger.debug('{0} bytes remaining'.format(len(data)))
            try:
                payload = payloads.get_by_type(next_payload,data)
            except KeyError as e:
                logger.error("Unidentified payload {}".format(e))
                payload = payloads._IkePayload(data=data)
            if payload._type == 33:
                self.esp_SPIout = payload.spi
            packet.payloads.append(payload)
            logger.debug('Payloads: {0!r}'.format(packet.payloads))
            next_payload = payload.next_payload
            data = data[payload.length:]
        logger.debug("Packed parsed successfully")
        self.packets.append(packet)
        if verify_flag:
            self.sign_verify(flag = flag)
            print "Signature verify successfully!"
        return packet
    
    def install_ipsec_sas(self,flag = True):
        
        print "Ipsec Vpn established successfully!"
        if flag:
            keymat = prfplus(self.SK_d, self.N + self.Nr)
        else:
            keymat = prfplus(self.SK_d, self.Ni + self.N)

        ( self.esp_ei,
          self.esp_ai,
          self.esp_er,
          self.esp_ar ) = unpack("16s20s16s20s", keymat[0:72])

        if flag:
            outbound_params = dict(spi=binascii.b2a_hex(self.esp_SPIout),
                                key_e=binascii.b2a_hex(self.esp_ei),
                                key_a=binascii.b2a_hex(self.esp_ai),
                                ip_from=self.address[0],
                                ip_to=self.peer[0])
            inbound_params = dict(spi=binascii.b2a_hex(self.esp_SPIin),
                                key_e=binascii.b2a_hex(self.esp_er),
                                key_a=binascii.b2a_hex(self.esp_ar),
                                ip_to=self.address[0],
                                ip_from=self.peer[0])
        else:
            outbound_params = dict(spi=binascii.b2a_hex(self.esp_SPIout),
                                key_e=binascii.b2a_hex(self.esp_er),
                                key_a=binascii.b2a_hex(self.esp_ar),
                                ip_from=self.address[0],
                                ip_to=self.peer[0])
            inbound_params = dict(spi=binascii.b2a_hex(self.esp_SPIin),
                                key_e=binascii.b2a_hex(self.esp_ei),
                                key_a=binascii.b2a_hex(self.esp_ai),
                                ip_to=self.address[0],
                                ip_from=self.peer[0])
        setkey_input = "{0}\n{1}\n{2}\n".format(
            ESP_ADD_SYNTAX.format( **outbound_params),
            ESP_ADD_SYNTAX.format( **inbound_params),
            SPDADD_SYNTAX.format(mysubip=self.left[0], peersubip=self.right[0],myip=self.address[0],peerip=self.peer[0]))
        print "adding outbound ESP SA\n\tSPI 0x{0},  src :{1}  dst :{2}".format(binascii.b2a_hex(self.esp_SPIout),self.address[0],self.peer[0])
        print "adding inbound ESP SA\n\tSPI 0x{0},  src :{1}  dst :{2}".format(binascii.b2a_hex(self.esp_SPIin),self.peer[0],self.address[0])
        
        file = open('../ipsec.conf','w')
        file.write(setkey_input)
        file.close()
        
        if os.system('setkey -f ../ipsec.conf') == 0:
            print 'ESP established successfully'


class Packet(object):
    """
    An IKE packet.

    To generate packets:

    #. instantiate an Packet()
    #. add payloads by Packet.add_payload(<payloads.IkePayload instance>)
    #. send bytes(Packet) to other peer.

    Received packets should be generated by IKE.parse_packet().
    """
    def __init__(self, data=None, exchange_type=None, message_id=0, iSPI=0, rSPI=0,flag = True):
        self.raw_data = data
        if exchange_type is None:
            exchange_type=const.ExchangeType.IKE_SA_INIT
        self.payloads = list()
        self.iSPI = iSPI
        self.rSPI = rSPI
        self.message_id = message_id
        self.exchange_type = exchange_type
        self.flag = flag    #flag = true: initiator        flag = flase: responder

    def add_payload(self, payload):
        """
        Adds a payload to packet, updating last payload's next_payload field
        """
        if self.payloads:
            self.payloads[-1].next_payload = payload._type
        self.payloads.append(payload)

    def __bytes__(self):
        if self.raw_data is not None:
            return self.raw_data
        data = reduce(operator.add, (x.__bytes__() for x in self.payloads))
        length = len(data) + const.IKE_HEADER.size
        if self.flag:
            flags = const.IKE_HDR_FLAGS['I']
        else:
            flags = const.IKE_HDR_FLAGS['R']
        header = bytearray(const.IKE_HEADER.pack(
            self.iSPI,
            self.rSPI,
            self.payloads[0]._type,
            const.IKE_VERSION,
            self.exchange_type,
            flags,
            self.message_id,
            length
        ))
        return bytes(header + data)





