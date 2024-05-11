from pwn import *
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from icecream import ic
from itertools import cycle

def xora(a,b) :
    return ''.join(chr(ord(i)^ord(j)) for i,j in zip(a,cycle(b)))
key=[]
ct=[]
for _ in range(2):
    r = remote('babycha.chal.irisc.tf', 10100)
    
    if _ == 0:
        for i in range(3):
            print(r.recvuntil(b'>'))
            r.sendline(b'1')
            if i == 0:
                r.sendline(b'\x00'*37)
            else:
                r.sendline(key[i-1])
            key.append(str(r.recvline().decode()[3:])[:-1])
            ic(key)
    else:
        for i in range(3):
            print(r.recvuntil(b'>'))
            r.sendline(b'2')
            ct.append(str(r.recvline().decode()[1:])[:-1])
            ic(ct)

for c,k in zip(ct,key):
    c=bytearray.fromhex(c)
    k=bytearray.fromhex(k)
    print(xor(c,k))

state = [0 for _ in range(16)]
state[0] = b2l(b"expa"[::-1])
state[1] = b2l(b"nd 3"[::-1])
state[2] = b2l(b"2-by"[::-1])
state[3] = b2l(b"te k"[::-1])
