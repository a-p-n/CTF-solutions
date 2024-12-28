import math
from BitVector import * 
from AESencryptfunc import *

PassPhrase = 'EncryptedLessons14821'
if(len(PassPhrase)<16):
    while(len(PassPhrase)!=16):
        PassPhrase=PassPhrase+"\00"
if(len(PassPhrase)>16):
    print("Your passphrase was larger than 16, truncating passphrase.")
    PassPhrase=PassPhrase[0:16]

ciphertext = "aa72fdd42a0befa9a7b4efcf62daccb3ae75f6db23a609b50c5b5c3166603ca95ec10a619ff8f4a55103ad93df30745d1d95fbd9db0c58e30e5d503f9b6b82e8ee3b0975cfb10f1552040a63846481f24f665385c30755f0bcbbf6c572698d52"
ciphertext = BitVector(hexstring = ciphertext)

PassPhrase=BitVector(textstring=PassPhrase)
roundkey1=findroundkey(PassPhrase.get_bitvector_in_hex(),1)
roundkey2=findroundkey(roundkey1,2)
roundkey3=findroundkey(roundkey2,3)
roundkey4=findroundkey(roundkey3,4)
roundkey5=findroundkey(roundkey4,5)
roundkey6=findroundkey(roundkey5,6)
roundkey7=findroundkey(roundkey6,7)
roundkey8=findroundkey(roundkey7,8)
roundkey9=findroundkey(roundkey8,9)
roundkey10=findroundkey(roundkey9,10)
roundkeys=[roundkey1,roundkey2,roundkey3,roundkey4,roundkey5,roundkey6,roundkey7,roundkey8,roundkey9,roundkey10]

bv2 = BitVector(hexstring = roundkeys[9])
bv1 = ciphertext ^ bv2



def inv_subbyte(myhexstring):
    loop2 = 0
    temp2 = ""
    for loop in range(0, math.ceil(len(myhexstring)/2)):
        x = int(myhexstring[loop2:loop2+2], 16) ^ 0xAA
        
        loop2 += 2
    return temp2

def inv_shiftrow(hexstring):
    # Assuming hexstring is a 32-character string representing 16 bytes
    matrix = [hexstring[i:i+2] for i in range(0, len(hexstring), 2)]
    # Inverse shift rows
    matrix[1], matrix[5], matrix[9], matrix[13] = matrix[13], matrix[1], matrix[5], matrix[9]
    matrix[2], matrix[6], matrix[10], matrix[14] = matrix[10], matrix[14], matrix[2], matrix[6]
    matrix[3], matrix[7], matrix[11], matrix[15] = matrix[7], matrix[11], matrix[15], matrix[3]
    return ''.join(matrix)

def inv_mixcolumn(bv3):
    eightlim = BitVector(bitstring='100011011')
    e = BitVector(bitstring='1110')
    b = BitVector(bitstring='1011')
    d = BitVector(bitstring='1101')
    nine = BitVector(bitstring='1001')

    newbv = BitVector(size=0)

    for i in range(0, 128, 32):
        bv = [bv3[i:i + 8], bv3[i + 8:i + 16], bv3[i + 16:i + 24], bv3[i + 24:i + 32]]

        tempbv = [
            bv[0].gf_multiply_modular(e, eightlim, 8) ^ bv[1].gf_multiply_modular(b, eightlim, 8) ^ bv[2].gf_multiply_modular(d, eightlim, 8) ^ bv[3].gf_multiply_modular(nine, eightlim, 8),
            bv[1].gf_multiply_modular(e, eightlim, 8) ^ bv[2].gf_multiply_modular(b, eightlim, 8) ^ bv[3].gf_multiply_modular(d, eightlim, 8) ^ bv[0].gf_multiply_modular(nine, eightlim, 8),
            bv[2].gf_multiply_modular(e, eightlim, 8) ^ bv[3].gf_multiply_modular(b, eightlim, 8) ^ bv[0].gf_multiply_modular(d, eightlim, 8) ^ bv[1].gf_multiply_modular(nine, eightlim, 8),
            bv[3].gf_multiply_modular(e, eightlim, 8) ^ bv[0].gf_multiply_modular(b, eightlim, 8) ^ bv[1].gf_multiply_modular(d, eightlim, 8) ^ bv[2].gf_multiply_modular(nine, eightlim, 8)
        ]

        for item in tempbv:
            newbv += item

    return newbv.get_bitvector_in_hex()