#Jared Staman
#CS 583: Secure Remote Password (SRP) protocol

import hashlib
from Crypto.Util import number

def main():

    #given
    g = 5
    p = 233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407
    
    #generate
    #a = number.getRandomInteger(512)
    a = 218327401406190993608449165793080428428450779004087234918287017304209718965817653702546977248953760965147785246330055730853024967982458628702141341098269

    #calculate public key (g^a)
    g_a = pow(g, a, p)
    
    #given
    username = "jstaman"
    password = "unpervious"
    salt = '0x96c960f2'
    iterations = 1000
    B = 218959443055370147423799729081010228278766320888577490748563377086786143151777687366966647022892018123752056572730040127704831347362610198576076699546157456168867187088381787906225526674523745424517195191510450498800995262379236217457969750852186966180514836250312809152692596850769670378805887074222000813013

    #calculate password hash as integer  (x = H(salt || password) ^iterations)

    #convert salt and password to byte arrays
    salt_bytes = bytes.fromhex(salt[2:])
    password_bytes = password.encode()
    #prepend salt to password
    bytes_array = salt_bytes + password_bytes
    #pass bytes array through sha256 1000 times
    digest = hashlib.sha256(bytes_array).digest()
    for i in range(1000 - 1):
        digest = hashlib.sha256(digest).digest()
    #convert bytes array to hexadecimal
    h = digest.hex()
    #convert to integer
    x = int(h, 16)
    #print(x)

    #calculate k = H(p || g) as integer
    p_bytes = p.to_bytes(129, 'big')
    g_bytes = g.to_bytes(1, 'big')
    digest = hashlib.sha256(p_bytes + g_bytes).digest()
    h = digest.hex()
    k = int(h, 16)
    #print(k)

    #calculate g^b = B - k*x(mod p)
    g_b = B - (k * pow(g, x, p) % p)
    #print(g_b)

    #calculate u = H(g^a || g^b)
    g_a_bytes = g_a.to_bytes(129, 'big')
    g_b_bytes = g_b.to_bytes(128, 'big')
    digest = hashlib.sha256(g_a_bytes + g_b_bytes).digest()
    h = digest.hex()
    u = int(h, 16)
    #print(u)

    #calculate shared key (g^b)^(a+u*x) (mod p)
    shared_key = pow(g_b, a + u*x, p)
    #print(shared_key)

    #calculate M1, the zero-knowledge proof that the Client knows the password
    #M1 = H( H(p) XOR H(g) || H(username) || salt || g^a || g^b || shared key)

    #H(p)
    digest = hashlib.sha256(p_bytes).digest()
    h = digest.hex()
    H_p = int(h, 16)

    #H(g)
    digest = hashlib.sha256(g_bytes).digest()
    h = digest.hex()
    H_g = int(h, 16)

    #XOR
    xor = H_p ^ H_g

    #take hash of username
    username_bytes = username.encode()
    username_bytes = hashlib.sha256(username_bytes).digest()

    #convert everything to bytes array
    xor_bytes = xor.to_bytes(32, 'big')
    shared_key_bytes = shared_key.to_bytes(128, 'big')
    
    #take hash of all bytes array prepended accordingly
    digest = hashlib.sha256(xor_bytes + username_bytes + salt_bytes + g_a_bytes + g_b_bytes + shared_key_bytes).digest()
    M1 = digest.hex()
    #print(M1)


    #calculate M2, the zero-knowledge proof that the Server knows the password
    #M2 = H( g^a || M1 || shared key)
    M1_bytes = digest
    digest = hashlib.sha256(g_a_bytes + M1_bytes + shared_key_bytes).digest()
    M2 = digest.hex()
    #print(M2)  

    return

if __name__ == "__main__":
    main()
