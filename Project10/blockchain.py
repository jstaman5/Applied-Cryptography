#Jared Staman
#CS 583: Blockchain Technology
#How to run: python blockchain.py

import hashlib
from Crypto.Util import number
from struct import *

def generate_block(prev_block, quote):
    #generate nonces until hash starts with at least 10 bits set to 0
    check = 0
    nonce = 11111111

    while(check != 1):
        nonce_bytes = nonce.to_bytes(3, 'big')
        digest = hashlib.sha256(prev_block + nonce_bytes + quote).digest()
        h = digest.hex()

        #check if at least first 10 bits of hash are 0
        first_12_bits = int(h[:3], base = 16)
        
        if('1' in bin(first_12_bits)):
            nonce += 1
        else:
            check = 1
            return (h, nonce)



def main():

    # H(block) = sha256(H(previous_block) || nonce || quote)

    #0th block in chain (given) in hex
    genesis = '0x5e096427e0d59b4e751e82d75b270331e2f403b4c5a50f4fdd72456bfdd93a9e'
    genesis_bytes = bytes.fromhex(genesis[2:])

    #block 1's quote, encode in ascii
    block1 = "The president was visiting NASA headquarters and stopped to talk to a man who was holding a mop. \"And what do you do?\" he asked. The man, a janitor, replied, \"I'm helping to put a man on the moon, sir.\" -- The little book of leadership"
    block1_bytes = block1.encode()

    #call function to get block's hash and nonce
    hash_hex, nonce = generate_block(genesis_bytes, block1_bytes)
    #print(hash_hex)
    #print(nonce)

    #block 2's quote
    block2 = "All creativity is an extended form of a joke. -- Alan Kay"
    block2_bytes = block2.encode()

    #getting hash and nonce for block 2
    hash_hex_bytes = bytes.fromhex(hash_hex)
    hash_hex2, nonce2 = generate_block(hash_hex_bytes, block2_bytes)
    #print(hash_hex2)
    #print(nonce2)

    #block 3's quote
    block3 = "I guess, when you're drunk, every woman looks beautiful and every language looks (like) a Lisp :) -- Lament, #scheme@freenode.net"
    block3_bytes = block3.encode()

    #hash and nonce for block 3
    hash_hex2_bytes = bytes.fromhex(hash_hex2)
    hash_hex3, nonce3 = generate_block(hash_hex2_bytes, block3_bytes)
    print(hash_hex3)
    print(nonce3)



if __name__ == "__main__":
    main()
