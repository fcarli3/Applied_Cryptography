#!/usr/bin/env python3
import sys
import time
#I seed my random generator
#A, C, and n are used in the libc! They MUST BE SECURE!
A=1103515245
C=12345
n=2**31
k0=int(input("Insert shared-secret (k0): "))
#Insert the message
pt = input("Message to be encrypted: \n")
if pt[0:6]!="From: ":
	print("For security reasons anonymous messages are not allowed!")
	exit()
while len(pt)%4!=0:
	pt+=' '
pt=pt.encode('ASCII')
ct=[]
ki=(A*k0+C)%n #first key
#Encrypt the message in 32-bit blocks! SUPER-SAFE!
for i in range(int(len(pt)/4)):
	ki_b = [ki%256, (ki>>8)%256, (ki>>16)%256, (ki>>24)%256] 
	ct+=[a^b for (a,b) in zip(ki_b,pt[i*4:i*4+4])]
	ki = (A*ki + C)%n #round key
#Write to file
with open("captured_ct_v2.txt", "wb") as f:
    f.write(bytes(ct))
    
#How to read bytes from a file
#f= open("<filename>", "rb")
#ct=list(f.read())

