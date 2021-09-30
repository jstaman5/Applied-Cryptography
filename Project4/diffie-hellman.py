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

def mod_exp(b, e, m):

    r = 1
    if 1 & e:
        r = b
    while e:
        e >>= 1
        b = (b * b) % m
        if e & 1: r = (r * b) % m
    return r

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