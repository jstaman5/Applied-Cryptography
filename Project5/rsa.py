#Jared Staman
#CS 583 Project 5: RSA

import hashlib
from Crypto.Util import number


def extended_euclidian(a,b):
    prev_x = 1
    prev_y = 0
    x = 1
    y = 1
    a_orig = a
    b_orig = b

    if( a > b):
        while b > 0:
            q = a // b
            a, b = b, a % b
            x, prev_x = prev_x - q*x, x
            y, prev_y = prev_y - q*y, y
    
        if prev_y < 0:
            return (prev_y + a_orig)

        return prev_y
    else:
        return extended_euclidian(b,a)


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
    return lx
def main():

    #print(multiplicative_inverse(5,72))
    #print(extended_euclidian(40,3))
    '''
    check = 0
    while(check == 0):
        p = number.getPrime(1024)
        q = number.getPrime(1024)
        n = p * q
        o = (p-1) * (q-1)
        if (o % 65537 != 0):
            check = 1
    '''
    e = 65537
    p = 127382144775808505803179292994174507579205678073520415123012872485015831762266459896810153830847868510534363834012123537971108315094609917867125180009125535867886794455409729284229879371987494763198830506606903800318079654789617888229570145689453039795051778911975330185291058827044393440529954722239941303567
    q = 151156893846855697227656160220640066509769691791539092778270589245781097868001592469746785201943940610937306054078754853314758714153936666810287647017741866085952991240288544345105359291360883229556298180208382782023288084886295009637530439697779781340956482975243811649447751382630752930266676281075395422707
    n = p*q
    o = (p-1) * (q-1)
    #print(f"{p}\n{q}\n{n}\n{o}")
    
    d = extended_euclidian(o, e)
    #print(d)
    message = "expropriations"
    utf8 = message.encode()
    h = utf8.hex()
    integer = int(h, 16)
        
    c = pow(integer, e, n)
    #print(c)

    c = 9340732215499379658618357608960018804924020028352647399388175376797970786382308300297826114936656561367906138870705745312540346683246748464933866307943011575098375070491563339278769846423970082189568332255124281457216719340595126025354324927341423721874458135977063714311478447612557745870897036469475403483679987804316132727199048935925809590245098454431112608956928316965155243642649515403822931388266018523978249954374093278261241040914007705525089679031594052446995433755105663158833718627842899961262464128394489208862466975048466690644102644379790268729759762470075464957555803572239246861767027796612878689790
    integer = pow(c, d, n)
    h = hex(integer)
    message = bytes.fromhex(h[2:])
    message = message.decode()
    print(message)
    
if __name__ == "__main__":
    main()
