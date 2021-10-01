#Jared Staman
#CS 583 Project 4: Diffie-Hellman

import hashlib
from Crypto.Util import number
from Crypto.Cipher import AES

#generates a prime whose (p-1)/2 is also a prime
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

    #multiply g by itself a times 
    while (a != 0):
        #right shift one (divides a by 2)
        a = a >> 1
        #square and then take mod
        g = (g * g) % p

        #if a is odd
        if(a % 2 != 0):
            #multiply by g, keep it modular by modding by p
            output = (output * g) % p
    
    return output

#getStrongPrime(1024)
p = 123169379117828169464046813292789428860836872824748369264296732639443218010560603258436048682596330887626356913181124303703014377062467835014718465253656878480036043823751652584591555569048587344199357191969518677994437189021877347538983787977642183702534721984911356665006945539110300659460332235330960998659
g = 5
a = 7724780111435172186712459324711487718618502753126076222366693329520251042158395098972334425448834005826683204720305851974473051022754593928834275775032496
#a = number.getRandomInteger(512)

m = mod_exp(g, a, p)

#given by passoff
gb = 31076449104896068573616438277936252646251489134571260181232266011362498335906612705475753505685726894111790843277545009489174039856750089928490738861003421638528048446455437018079745150618545289686742629517690643491030795405330528073858279170832596454360598823783169864972754161271066565192147692450933050029

m2 = mod_exp(gb, a, p)


h = hashlib.sha256()
hex = hex(m2)

hex_string = bytes.fromhex(hex[2:])

#given by passoff
IV = '0xab1382edaebef0f595b2900d5f63ffdb'
ciphertext = '0x07bad3f971d62114224b9bc8db1281416219e4c2ae41724cf00a974faefc714c35f0fb32162d92e37ec8a9025e51aad4dc0dd69277af1a5628638ffafc19902e'
ct = bytes.fromhex(ciphertext[2:])

h.update(hex_string)
h = h.hexdigest()[:32]
key = bytes.fromhex(h)

IV = bytes.fromhex(IV[2:])
cipher = AES.new(key, AES.MODE_CBC, iv = IV)

plaintext = cipher.decrypt(ct).decode("ascii")
print(plaintext)