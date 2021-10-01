Jared Staman
CS 583 Project 4: Diffie-Hellman

How to run:
python diffie-hellman.py


This program performs the Diffie-Hellman algorithm to decrypt a message. It first 
generates a 1024 bit strong prime number as a 'p' value. Our 'g' value is 5 and 'a' value is a
random 512 bit number. Then the program performs modular exponentation to generate the 
g^a (mod p) value. This value is passed to the passoff, which returns a g^b (mod p)
value. Then the program calculates the g^a*b (mod p) value. The first 16 bytes in hex of
this value is the symmetric key. This key and a given IV value is used to decrypt
a message that the passoff system gives. 