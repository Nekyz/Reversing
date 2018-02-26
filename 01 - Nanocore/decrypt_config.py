#!/usr/bin/python3

import re
import io
import uuid
import zlib
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES, DES
from struct import *

guid = "94c8727d-349f-48c9-8157-aa2ea8af4be6"
guid = uuid.UUID(guid).bytes_le

f = open("1", mode='rb')

bkey_length = f.read(4)
ikey_length = int.from_bytes(bkey_length, byteorder="little")

print("[-] Key Length: %s" % ikey_length)

bEncrypted_key = f.read(ikey_length)

pbkey = PBKDF2(guid,guid,8)

rijndaelManaged_iv = pbkey.read(16)
rijndaelManaged_key = pbkey.read(16)

# AES Stuff from 
a = AES.new(rijndaelManaged_key, AES.MODE_CBC, rijndaelManaged_iv)

key = a.decrypt(bEncrypted_key)

print('[-] Key gotten : %s' % (key))
# DES from class22.smethod0
# Key = IV = byte_0 which is the previous key. 
key = key[0:8]

b = DES.new(key, DES.MODE_CBC, key)

#Get Size of the configuration
bConf_length = f.read(4)
iConf_length = int.from_bytes(bConf_length, byteorder="little")

print("[-] Conf Length: %s" % (iConf_length))

encoded_configuration = f.read(iConf_length)

decrypted_conf = b.decrypt(encoded_configuration)

print("[-] First value is %s" % decrypted_conf[0])

if not (decrypted_conf[0] == 0):
	bdecryption_length = decrypted_conf[1:4]
	idecryption_length = int.from_bytes(bdecryption_length, byteorder="little")
	print("[-] Deflate length: %s" % idecryption_length)
	c = decrypted_conf[5:] # Remove the first 5 bytes as NanoCore read a Boolean then an Int32 from the decrypted data for the array to create. 
	conf = zlib.decompress(c,-zlib.MAX_WBITS)
else:
	conf = decrypted_conf


with open("decoded_configuration", 'wb') as output_file:
	output_file.write(conf)

stream_conf = io.BytesIO(conf)

# In C# they gather the first two bytes of the conf and store them in two variables
bytes_0 = stream_conf.read(1)
bytes_1 = stream_conf.read(1)

# Create GUID in if the next value is not false 
if not (stream_conf.read(1) == b'\x00'):
	print("[-] Got UUID")
	binary_uuid = stream_conf.read(16)
	gathered_uuid = uuid.UUID(bytes_le=binary_uuid)

f.close() 

j = 150
#Handling of the massive switch in C#
while(True):
	i = stream_conf.read(1)
	if i == '':
		# EOF
		break
	if i == b'\x00':
		print("[-] Got Boolean : %s" % unpack('?',stream_conf.read(1))[0])
	elif i == b'\x01':
		print("[-] Got a byte : %s" % stream_conf.read(1))
	elif i == b'\x02' : 
		length = unpack('i', stream_conf.read(4))[0]
		print("[-] Got a byte of length : %s" % length)
		with open(str(j), 'wb') as opt: 
			opt.write(stream_conf.read(length))
		j += 1		
	elif i == b'\x03':
		print("[-] Got a Char: %s" % unpack('b',stream_conf.read(1))[0])

#The string length is encoded on 7 bits in C# stream, and I didn't want to waste too much time, so, I stopped here for the parsing of the data. 

