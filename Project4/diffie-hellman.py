#Jared Staman
#CS 583 Project 4: Diffie-Hellman

from Crypto.Util import number
def getStrongPrime(bits):
    check = 0
    traversals = 0
    while(check == 0):
        num = number.getPrime(bits)
        traversals += 1
        num2 = (num-1) // 2
        if( number.isPrime( num2)):
            check = 1

    print(num)
    print(traversals)
    return

#modular exponentiation
def mod_exp(g, a, p):

    output = 1

    
    while (a != 0):
        a = a >> 1
        g = (g * g) % p
        if(a & 1 != 0):
            output = (output * g) % p
    return output

#getStrongPrime(1024)
p = 123169379117828169464046813292789428860836872824748369264296732639443218010560603258436048682596330887626356913181124303703014377062467835014718465253656878480036043823751652584591555569048587344199357191969518677994437189021877347538983787977642183702534721984911356665006945539110300659460332235330960998659
g = 5
a = 7724780111435172186712459324711487718618502753126076222366693329520251042158395098972334425448834005826683204720305851974473051022754593928834275775032496
#a = number.getRandomInteger(512)
#print(a)
#print(num)
n = pow(g, a, p)
m = mod_exp(g, a, p)
print(n)
print(m)

l = 0b00000001
k = 0b00000001
print(l & k)