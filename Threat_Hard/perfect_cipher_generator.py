#!/usr/bin/env python3
import sys
import random
import time

#I seed my random generator
random.seed(time.time())

#I choose at random my parameters for LCG
#GOOD LUCK BRUTEFORCING THEM! AHAHAHAHAHAHAHAHAHAHAHAHAHAH
A = random.randrange(2**128)
C = random.randrange(2**128)
n = 256
k0 = int(input("Insert shared-secret (k0): "))
k0 = k0%n

#Insert the message
pt = input("Message to be encrypted: \n")
if pt[0:6] != "From: ":
	print("For security reasons anonymous messages are not allowed!")
	exit()
pt = pt.encode('ASCII')
ct = []
ki = k0

print(f'A --> {A}')
print(f'C --> {C}')

#Encrypt the plaintext
for i in range(len(pt)):
	ct.append(ki ^ pt[i])
	ki = (A*ki + C)%n
	
#Write the ciphertext in file ciphertext.txt
with open("ciphertext.txt", "wb") as f:
    f.write(bytes(ct))
 
#Print ciphertext's bytes
file = open("captured_ct.txt","rb")
ct = list(file.read())
print(f'Ciphertext: {ct}')
