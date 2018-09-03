#!/usr/bin/env python  
# -*- coding:utf-8 -*-

from OpenSSL.crypto import load_privatekey, FILETYPE_ASN1,FILETYPE_PEM, sign,load_certificate,verify
import hmac
import hashlib
from binascii import b2a_hex, a2b_hex
from Crypto.Util.number import long_to_bytes, bytes_to_long

def priv_sign(signed,length):

# 私钥签名验证auth载荷 
	#ID initiator 载荷
	RealMessage1 = signed[:length]
	Nr = signed[length:length+32]
	length += 32
	sk_pi = signed[length:length+32]
	length += 32
	InitIDPayload = signed[length:len(signed)]
	MACedIDForI = a2b_hex(hmac.new(sk_pi, InitIDPayload, digestmod=hashlib.sha256).hexdigest()) #hash值
	
	#整个IKE数据包
	InitiatorSignedOctets = RealMessage1 + Nr + MACedIDForI #签名内容
	
	key = load_privatekey(FILETYPE_PEM, open("/home/sjx/桌面/clientkey.pem").read(),'123456')
	AuthenticationPayloadOfInitiator = sign(key,InitiatorSignedOctets,'sha256') # 签名值
	return AuthenticationPayloadOfInitiator,InitiatorSignedOctets   #####测试
	 
def pubkey_verify(buffer,signature,data,sha):
	#modules = "00e096525f9f20f1b55f3ab017f74d20f75487d92977c7e60b251fe51e1f84eb338469dc21835995635e77067575ff5f6281784850ac14a58beb1fcbe935b124e531d236ea34ffa7bcc6299a3ee62272b398c342427ee052da2c55a5dd57ec38bab92afcca36464b3f7c26d5e29a24b87bec18a0f27f2232174ccec0d2acbfd673"
	# e = int(e,16) #65537
	# n = int(modules, 16)
	# key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
	# print type(key)
	# pem = key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
	# with open('./pubkey.pem', 'w+') as f:
	# 	f.writelines(pem.decode())
	# #pubkey = load_publickey(FILETYPE_PEM,open("pubkey.pem").read())
	# return verify("pubkey.pem",sign,data,'sha256')

	#key = pow(bytes_to_long(signature), bytes_to_long(e), bytes_to_long(modules))  # B**a % p == g**ba % p
	#print b2a_hex(long_to_bytes(key,32))
	#print hashlib.sha256(data).hexdigest()
	#return a2b_hex(hashlib.sha256(data).hexdigest()) == long_to_bytes(key,256)


	cert = load_certificate(FILETYPE_ASN1,buffer)
	verify(cert,signature,data,sha)
	
