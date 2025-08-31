#!/usr/bin/env python3

from os import urandom, environ
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from string import ascii_lowercase, digits
from secrets import choice
import signal

FLAG = environ.get("FLAG", "snakeCTF{fakeflag}")
TIMEOUT = environ.get("TIMEOUT", 300)
SECRET_LEN = 15
key_len = SECRET_LEN // 3
secret_token = ''.join([choice(ascii_lowercase + digits) for _ in range(SECRET_LEN)])
seeds = [secret_token[i:i+key_len] for i in range(0, len(secret_token), key_len)]
keys = [sha256(seed.encode()).digest()[:16] for seed in seeds]
ivs = [urandom(16), urandom(16)]


def xor(a:bytes, b:bytes):
    return bytes([x ^ y for x,y in zip(a, b)])


def encrypt(pt:bytes, keys:list, ivs:list) -> bytes:
    cipher1 = AES.new(keys[0], AES.MODE_ECB)
    cipher2 = AES.new(keys[1], AES.MODE_OFB, ivs[0])
    cipher3 = AES.new(keys[2], AES.MODE_CBC, ivs[1])

    ct1 = cipher1.encrypt(pad(pt, 16))
    ct2 = cipher2.encrypt(ct1)
    twks = [sha256(ivs[1] + i.to_bytes(1, 'big')).digest()[:16] for i in range(0, len(ct2)//16)]
    ct3 = cipher3.decrypt(xor(ct2, b''.join(twks)))

    return ct3


def main():
    print('Can you guess my secret token?')
    try:
        pt = bytes.fromhex(input('Give me a plaintext to encrypt (in hex): '))
        ct = encrypt(pt, keys, ivs)
        print(f'Ciphertext (in hex): {''.join([iv.hex() for iv in ivs]) + ct.hex()}')
        st = input('Give me your guess: ')
        if st == secret_token:
            print(f'Well done, here is the flag: {FLAG}')
        else:
            print('Nope.')
    except:
        exit('Something went wrong')


if __name__ == '__main__':
    signal.alarm(TIMEOUT)
    main()
