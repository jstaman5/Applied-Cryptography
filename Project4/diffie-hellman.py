#Jared Staman
#CS 583 Project 4: Diffie-Hellman

from Crypto.Util.number import getRandomInteger
from Crypto.Util.number import getPrime
from Crypto.Util.number import isPrime

def getStrongPrime(bits):
    check = 0
    while(check == 0):
        num = getPrime(bits)
        num2 = (num-1) // 2
        if( isPrime( num2)):
            check = 1

    print(num)
    return

getStrongPrime(1024)
