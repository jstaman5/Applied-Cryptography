#Jared Staman
#CS 583 Lab 3: Mac Attack
#Sha-1 implementation taken from https://github.com/TheAlgorithms/Python/blob/master/hashes/sha1.py

import argparse
import hashlib  # hashlib is only used inside the Test class
import struct
import unittest
import sys

def sha1_padding(msg, forced_msg_byte_length=None):

    #length of message in bits
    if forced_msg_byte_length == None:                                                                 #Edit made by me: change padding when performing attack to include Alice msg + padding
        msg_length = len(msg)*8 
    else:
        msg_length = forced_msg_byte_length*8

    m = -(msg_length + 1 + 64) % 512

    padded_msg = (msg + bytes([0b10000000]) + b'\x00'*(m//8) + msg_length.to_bytes(8, byteorder='big')
                 )

    return padded_msg


class SHA1Hash:
    """
    Class to contain the entire pipeline for SHA1 Hashing Algorithm
    >>> SHA1Hash(bytes('Allan', 'utf-8')).final_hash()
    '872af2d8ac3d8695387e7c804bf0e02c18df9e6e'
    """

    def __init__(self, data, mac_hash=None):
        """
        Inititates the variables data and h. h is a list of 5 8-digit Hexadecimal
        numbers corresponding to
        (1732584193, 4023233417, 2562383102, 271733878, 3285377520)
        respectively. We will start with this as a message digest. 0x is how you write
        Hexadecimal numbers in Python
        """
        self.data = data
        if(mac_hash == None):                                                                                 #Edit by me: change the starting mac_hash to start with correct Mac
            self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        else:
            self.h = mac_hash
    
    @staticmethod
    def rotate(n, b):
        """
        Static method to be used inside other methods. Left rotates n by b.
        >>> SHA1Hash('').rotate(12,2)
        48
        """
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def padding(self, message_added_length=None):
        """
        Pads the input message with zeros so that padded_data has 64 bytes or 512 bits
        """

        
        padding = b"\x80" + b"\x00" * (63 - (len(self.data) + 8) % 64)
        if(message_added_length==None):                                                                                     #Edit made by me: change padding when message extension
            padded_data = self.data + padding + struct.pack(">Q", 8 * len(self.data))
        else:
            padded_data = self.data + padding + struct.pack(">Q", 8 * (len(self.data) + message_added_length))

        return padded_data

    def split_blocks(self):
        """
        Returns a list of bytestrings each of length 64
        """
        return [
            self.padded_data[i : i + 64] for i in range(0, len(self.padded_data), 64)
        ]

    # @staticmethod
    def expand_block(self, block):
        """
        Takes a bytestring-block of length 64, unpacks it to a list of integers and
        returns a list of 80 integers after some bit operations
        """
        w = list(struct.unpack(">16L", block)) + [0] * 64
        for i in range(16, 80):
            w[i] = self.rotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1)
        return w

    def final_hash(self, message_added_length=None):
        """
        Calls all the other methods to process the input. Pads the data, then splits
        into blocks and then does a series of operations for each block (including
        expansion).
        For each block, the variable h that was initialized is copied to a,b,c,d,e
        and these 5 variables a,b,c,d,e undergo several changes. After all the blocks
        are processed, these 5 variables are pairwise added to h ie a to h[0], b to h[1]
        and so on.  This h becomes our final hash which is returned.
        """
        self.padded_data = self.padding(message_added_length)
        self.blocks = self.split_blocks()
        for block in self.blocks:
            expanded_block = self.expand_block(block)
            a, b, c, d, e = self.h
            for i in range(0, 80):
                if 0 <= i < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i < 80:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                a, b, c, d, e = (
                    self.rotate(a, 5) + f + e + k + expanded_block[i] & 0xFFFFFFFF,
                    a,
                    self.rotate(b, 30),
                    c,
                    d,
                )
            self.h = (
                self.h[0] + a & 0xFFFFFFFF,
                self.h[1] + b & 0xFFFFFFFF,
                self.h[2] + c & 0xFFFFFFFF,
                self.h[3] + d & 0xFFFFFFFF,
                self.h[4] + e & 0xFFFFFFFF,
            )
        return "%08x%08x%08x%08x%08x" % tuple(self.h)


class SHA1HashTest(unittest.TestCase):
    """
    Test class for the SHA1Hash class. Inherits the TestCase class from unittest
    """

    def testMatchHashes(self):
        msg = bytes("Test String", "utf-8")
        self.assertEqual(SHA1Hash(msg).final_hash(), hashlib.sha1(msg).hexdigest())


def main():
    """
    Provides option 'string' or 'file' to take input and prints the calculated SHA1
    hash.  unittest.main() has been commented because we probably don't want to run
    the test each time.
    """

    '''
    # unittest.main()
    parser = argparse.ArgumentParser(description="Process some strings or files")
    parser.add_argument(
       # "--string",
        dest="input_string",
        default="Hello World!! Welcome to Cryptography",
        help="Hash the string",
    )
    parser.add_argument("--file", dest="input_file", help="Hash contents of a file")
    args = parser.parse_args()
    input_string = args.input_string
    # In any case hash input should be a bytestring
    if args.input_file:
        with open(args.input_file, "rb") as f:
            hash_input = f.read()
    else:
        #hash_input = bytes(input_string, "utf-8")
        input_string2 = "hello"
        hash_input = bytes(input_string2, "utf-8")
    print(SHA1Hash(hash_input).final_hash())
    '''
    #TESTING
    msg = sys.argv[1]
    new_msg = sys.argv[2]

    key = "0000000000000000"
    #msg = "No one has completed Project #3 so give them all a 0."
    keysize = 16
    #new_msg = "Except Jared Staman, give him a 100."
    hash_input = bytes(msg, "utf-8")
    key = bytes(key, "utf-8")
    mac = SHA1Hash(key+hash_input).final_hash()

    mac_hash2 = [mac[i:i+8] for i in range(0, len(mac), 8)]
    mac_hash = []
    for x in mac_hash2:
        s = x
        i = int(s, 16)
        mac_hash.append(i)
    new_msg = bytes(new_msg, "utf-8")
        
    padding = sha1_padding(key+hash_input)[keysize + len(hash_input):]
    #print(padding.hex())
    message_added_length = keysize + len(hash_input) + len(padding)


  # test to check if the attack works
    print(SHA1Hash(new_msg, mac_hash).final_hash(message_added_length))
    forged_msg = hash_input + padding + new_msg
    print(SHA1Hash(key+forged_msg).final_hash())


if __name__ == "__main__":
    main()
