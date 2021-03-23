#!/usr/bin/env python3
import sys
import random
import time

#Si potrà fare il bruteforce sui valori di A e C sfruttando la seguente proprietà:
#
#In un espressione in modulo posso applicare il modulo ad ogni operando e poi all'espressione intera
# (A*k + C) mod n = ((A mod n)*k + (C mod n)) mod n
#
#In questo modo si potrà restringere il range di ricerca, passando da 2^128 a 2^8 sia per A che per C
#Si avrà A = A mod 256 e C = C mod 256
#
#Potrò sfruttare ciò unito al fatto che ogni messaggio cifrato inizia con 'From: ', quindi posso impostare un
#sistema con due incognite osservando i bytes del testo cifrato
# 'F' xor k0 = 213 --> ko = 147
# 'r' xor k1 = 114 --> k1 = 111
# 'o' xor k2 = 111 --> k2 = 35

# Ottengo i bytes del testo cifrato
path = input("File da decifrare: ")
file = open(path,"rb")
ct = list(file.read())

final_A = 0
final_C = 0
n = 256
pt = []
known_pt = 'From: '.encode('ASCII') 

k0 = ct[0] ^ known_pt[0]
k1 = ct[1] ^ known_pt[1]
k2 = ct[2] ^ known_pt[2]

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

#Scrivo il testo in chiaro sul file out.txt
with open("out.txt", "wb") as f:
    f.write(bytes(pt))


