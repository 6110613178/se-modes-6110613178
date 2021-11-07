#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from binascii import hexlify as hexa
from os import urandom

#Material
k = bytearray(16) # 0 = 128 bits
iv = urandom(16)

#ID
usernameEncode = '6110613178'.encode('utf-8')
id = usernameEncode.hex()

#M1
M1 = ''
while len(M1)+len(id) < 96 :
    M1 += id
while len(M1) < 96 :
    M1 += '0'

print(M1)

M1_encode = M1.encode()
M1_bytes = bytes(M1_encode)

#M2
oneBits = ''
for i in M1:
    oneBits = oneBits + 'f'
M2 = hex(int(M1, base=16) ^ int(oneBits, base=16))[2:]

print(M2)

M2_encode = M2.encode()
M2_bytes = bytes(M2_encode)

#M3
anyBits = ''
for i in range(len(M2)):
     if (i < 64):
          anyBits = anyBits + 'f'
     else :
          anyBits = anyBits + '0'
M3 = hex(int(M2,base=16) ^ int(anyBits,base=16))[2:]

print(M3)

M3_encode = M3.encode()
M3_bytes = bytes(M3_encode)

#Mode
cipher = Cipher(
    algorithms.AES(k),
    modes.CBC(iv)
)

#Encrypt
aes_encrypt = cipher.encryptor()

c1 = aes_encrypt.update(M1_bytes)
c1_hex = c1.hex()
print(c1_hex)

c2 = aes_encrypt.update(M2_bytes)
c2_hex = c2.hex()
print(c2_hex)

c3 = aes_encrypt.update(M3_bytes) + aes_encrypt.finalize()
c3_hex = c3.hex()
print(c3_hex)

#Decrypt
aes_decrypt = cipher.decryptor()

p1 = aes_decrypt.update(c1)
p1_hex = p1.decode('latin-1')
print(p1_hex)

p2 = aes_decrypt.update(c2)
p2_hex = p2.decode('latin-1')
print(p2_hex)

p3 = aes_decrypt.update(c3) + aes_decrypt.finalize()
p3_hex = p3.decode('latin-1')
print(p3_hex)

