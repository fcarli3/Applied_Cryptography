#!/usr/bin/env python3

#Per risolvere l'esercizio so i primi caratteri che sono sempre 'From: ', quindi faccio lo xor con i primi 4 caratteri del testo cifrato.
#In questo modo trovo i primi 4 bytes di ki_b, da cui posso trovare ki.
#Così trovo la prima chiave ki della sequenza e da qui posso ricostruire le chiavi successive

A = 1103515245
C = 12345
n = 2**31
pt = []

#Leggo i bytes dal file contenente il testo cifrato
f = open("captured_ct_easy.txt", "rb")
ct = list(f.read())

#Faccio lo xor tra testo cifrato e testo in chiaro per ottenere i primi 4 bytes di ki_b
test = 'From: '.encode('ASCII') #ottengo il formato ASCII della stringa 'From: '
ki_b = [test[0]^ct[0], test[1]^ct[1], test[2]^ct[2], test[3]^ct[3]] #faccio lo xor tra carattere del testo cifrato e carattere del testo in chiaro

#Ricostruisco ki effettuando uno shift al contrario dei bytes di ki_b
ki = ki_b[3]<<24 | ki_b[2]<<16 | ki_b[1]<<8 | ki_b[0]

for i in range(int(len(ct)/4)):
	pt += [a^b for (a,b) in zip(ki_b,ct[i*4:i*4+4])] #qua faccio lo xor tra i bytes di ki_b e quelli del testo cifrato
	ki = (A*ki + C)%n #calcolo la successiva chiave ki
	ki_b = [ki%256, (ki>>8)%256, (ki>>16)%256, (ki>>24)%256] #modifico i bytes della chiave appena calcolata
	
#Scrivo il testo in chiaro sul file out.txt
with open("out.txt", "wb") as f:
    f.write(bytes(pt))
    


