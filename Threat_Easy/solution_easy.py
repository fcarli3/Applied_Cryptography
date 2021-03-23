#!/usr/bin/env python3

A = 1103515245
C = 12345
n = 2**31
pt = []

#Read bytes from ciphertext's file
f = open("captured_ct_easy.txt", "rb")
ct = list(f.read())

#Xor between ciphertext and plaintext to obtain first 4 bytes of ki_b
test = 'From: '.encode('ASCII') #ASCII of string 'From: '
ki_b = [test[0]^ct[0], test[1]^ct[1], test[2]^ct[2], test[3]^ct[3]] 

#Rebuild of ki
ki = ki_b[3]<<24 | ki_b[2]<<16 | ki_b[1]<<8 | ki_b[0]

for i in range(int(len(ct)/4)):
	pt += [a^b for (a,b) in zip(ki_b,ct[i*4:i*4+4])] 
	ki = (A*ki + C)%n 
	ki_b = [ki%256, (ki>>8)%256, (ki>>16)%256, (ki>>24)%256] 
	
#Write the plaintext in a file
with open("out.txt", "wb") as f:
    f.write(bytes(pt))
    


