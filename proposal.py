# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#
"""
Implements Proposal and Transform substructures for Security association (SA) payloads.

Conforms to `RFC5996 section 3.3 <https://tools.ietf.org/html/rfc5996#section-3.3>`_
"""
from functools import reduce
import logging
import os
import operator
import struct
import binascii

import const

__author__ = 'kimvais'

logger = logging.getLogger(__name__)


class Proposal(object):
    def __init__(self, data=None, num=1, protocol=const.ProtocolID.IKE, spi=None, spi_len=0,
                 last=False, transforms=None):
        if data is not None:
            self.parse(data)
        else:
            if transforms == None:
                self.transforms = list()
            else:
                self.transforms = [Transform(*x) for x in transforms]
                self.transforms[-1].last = True
            self.last = last
            self.num = num
            self.protocol_id = protocol
            if spi is not None:
                spi_str = spi
                self.spi_len = len(spi)
            else:
                self.spi_len = spi_len
            if not self.spi_len:
                if protocol == const.ProtocolID.IKE:
                    self.spi_len = 8
                elif protocol in (const.ProtocolID.ESP, const.ProtocolID.AH):
                    self.spi_len = 4
                spi_str = os.urandom(self.spi_len)   #字节流
            if self.spi_len == 8:
                self.spi = struct.unpack('!Q', spi_str)[0]    #8字节整型值(64位)
            elif self.spi_len == 4:
                self.spi = struct.unpack('!L', spi_str)[0]

            if protocol == const.ProtocolID.IKE:
                self.spi_len = 0
    @property
    def data(self):
        self.transforms[-1].last = True
        parts = [x.data for x in self.transforms]
        self.len = const.PROPOSAL_STRUCT.size + self.spi_len + sum(
            len(x) for x in parts)
        if self.last:
            last = 0
        else:
            last = 2
        parts.insert(0, bytearray(const.PROPOSAL_STRUCT.pack(
            last,
            0,
            self.len,
            self.num,
            self.protocol_id,
            self.spi_len,
            len(self.transforms),
        )))
        if self.spi_len == 4:
            spi = struct.pack('!L', self.spi)
            parts.insert(1, spi)

        return reduce(operator.add, parts)

    def parse(self, data):
        last, _, self.len, self.num, self.protocol_id, self.spi_len, self.transform_count = const.PROPOSAL_STRUCT.unpack(
            data[:const.PROPOSAL_STRUCT.size])
        self.last = False if last == 2 else True
        logger.debug(
            'Last?:{0}, Len:{1}, Num:{2}, Protocol ID:{3}, SPI len:{4}, Transforms:{5}'.format(
                self.last, self.len, self.num, self.protocol_id, self.spi_len,
                self.transform_count))
        if self.spi_len:
            self.spi = data[const.PROPOSAL_STRUCT.size:const.PROPOSAL_STRUCT.size + self.spi_len]
            #logger.debug('SPI: {0}'.format(hex(self.spi)))
        else:
            self.spi = None


class Transform(object):
    def __init__(self, name, keysize=None, last=False):
        super(Transform, self).__init__()
        self.attributes = list()
        self.last = last
        self.transform_type, self.transform_id = const.TRANSFORMS[name]
        self.keysize = keysize
        if self.transform_type == 1 and self.keysize is not None:
            self.attributes.append(const.TRANFORM_ATTRIBUTES.pack(
                (0b1000000000000000 | 14), self.keysize))
        self.len = (
            const.TRANSFORM_STRUCT.size +
            const.TRANFORM_ATTRIBUTES.size * len(self.attributes))

    @property
    def data(self):
        last = 0 if self.last else 3
        ret = bytearray(
            const.TRANSFORM_STRUCT.pack(
                last, 0, self.len,
                self.transform_type, 0, self.transform_id))
        for attr in self.attributes:
            ret += attr
        return ret
