#!/usr/bin/env python3
import sys
import random
import time

# A and C values can be bruteforced thanks to the following properties:
#
# (A*k + C) mod n = ((A mod n)*k + (C mod n)) mod n
#
# That way, the range of all possible values of A and C passes from 2^128 to 2^8.
# A = A mod 256 and C = C mod 256
#
# Moreover, we know all messages start with 'From: ', then we are able to build a linear system: 
# 'F' xor k0 = 213 --> ko = 147
# 'r' xor k1 = 114 --> k1 = 111
# 'o' xor k2 = 111 --> k2 = 35
# ...

# Bytes of the ciphertext
path = input("File to decrypt: ")
file = open(path, "rb")
ct = list(file.read())

final_A = 0
final_C = 0
n = 256
pt = []
known_pt = 'From: '.encode('ASCII') 

k0 = ct[0] ^ known_pt[0]
k1 = ct[1] ^ known_pt[1]
k2 = ct[2] ^ known_pt[2]

#Bruteforce attack
for A in range(0,255):
	for C in range(0, 255):
	
		eq1 = (k1 == ((A*k0) + C) % n)
		eq2 = (k2 == ((A*k1) + C) % n)
	
		if(eq1 == True and eq2 == True):
			final_A = A
			final_C = C
			break
			
ki = k0
for i in range(int(len(ct))):
	pt.append(ct[i] ^ ki)
	ki = ((final_A*ki) + final_C) % n

print(f'A --> {final_A}')
print(f'C --> {final_C}')

#Write the plaintext into file out.txt 
with open("out.txt", "wb") as f:
    f.write(bytes(pt))


