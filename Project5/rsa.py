#Jared Staman
#CS 583 Project 5: RSA

import hashlib
from Crypto.Util import number


def extended_euclidian(x,y):
    pass

def multiplicative_inverse(a, b):
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    # return a , lx, ly  # Return only positive values
    return ly
def main():

    print(multiplicative_inverse(40,3))
    print(extended_euclidian(72,5))
    '''
    check = 0
    while(check == 0):
        p = number.getPrime(1024)
        q = number.getPrime(1024)
        n = p * q
        o = (p-1) * (q-1)
        if (o % 65537 != 0):
            check = 1

    print(f"{p}\n{q}\n{n}\n{o}")
    '''
    
    
if __name__ == "__main__":
    main()
