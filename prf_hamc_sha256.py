#!/usr/bin/env python  
# -*- coding:utf-8 -*-   

import hmac
import hashlib
from binascii import b2a_hex, a2b_hex  

def key_generator(Ni,Nr,g_ir = None,SPIi = None,SPIr = None):   # 字节流
	
	#print b2a_hex(Ni)
	#print b2a_hex(Nr)

	#接口
	#Ni = a2b_hex('7af59e86186c8a5e18b456f91a9462c03d3defb9a576d123295d7094c5776a37')
	#Nr = a2b_hex('ef1d1d44deec08e69a71fb2b2520cbbffdb7e8e4c7491c81e20922bb76362e15')
	#g_ir = a2b_hex("00C000CD43C43B7269C81F9F89B8BE9A9C885AA0165C001E1359FECEB0E7119D3B0AD698022142789DF54CDA976283307AA8E723C65211812A49DDAE11B8CA7D017066E93D66472DFF740C47309DD5B610EC393F9508E4A526044DD3E09CF7F544EE8513EC3A6E7A664319D98FA233065F883124F6FC1AAC9EB4E5436A2F28CE7C25B192F79529A7502D155F4AC6ECE5ECF7FCBE76C277BBB92AB4240E314584967131EA6A9D337F9A72AD1CC04EC29B05CE6ACEFAAAADBB6ABD5F50EA10B165AF51AE1C94ABC5D9A1EE80C002B10033B2813B95C8512D05AFE795B3F18B830E399827FCE54F591EDACAD377565544FD9BE80D5F292E708C93E8CF5EE656D428")

	key = Ni + Nr
	data = g_ir
	SKEYSEED = hmac.new(key, data, digestmod=hashlib.sha256).hexdigest()
	
	#print "加密:",SKEYSEED,len(a2b_hex(SKEYSEED))
	
	#SPIi = a2b_hex('5f7fb0b0fe61bf49')
	#SPIr = a2b_hex('a7a31b524795d50c')
	K = a2b_hex(SKEYSEED)
	S = Ni + Nr + SPIi + SPIr
	T = ''
	TotalKey = ''
	for i in range(1, 10): # 10 次循环足够生成所需密钥
		count_byte = a2b_hex('%02d' % i) # 0x01 0x02 0x03 ...
		data = T + S + count_byte
		T = hmac.new(K, data, digestmod=hashlib.sha256).hexdigest()
		T = a2b_hex(T)
		TotalKey += T
	
	#print len(TotalKey)
	SK_d  = TotalKey[0:32]
	SK_ai = TotalKey[32:32+32]
	SK_ar = TotalKey[64:64+32]
	SK_ei = TotalKey[96:96+16]
	SK_er = TotalKey[112:112+16]
	SK_pi = TotalKey[128:128+32]
	SK_pr = TotalKey[160:160+32]

	# print 'SK_d  = ' + b2a_hex(SK_d)
	# print 'SK_ai = ' + b2a_hex(SK_ai)
	# print 'SK_ar = ' + b2a_hex(SK_ar)
	# print 'SK_ei = ' + b2a_hex(SK_ei)
	# print 'SK_er = ' + b2a_hex(SK_er)
	# print 'SK_pi = ' + b2a_hex(SK_pi)
	# print 'SK_pr = ' + b2a_hex(SK_pr)

	#return SK_d,SK_ai,SK_ar,SK_ei,SK_er,SK_pi,SK_pr
	return TotalKey
