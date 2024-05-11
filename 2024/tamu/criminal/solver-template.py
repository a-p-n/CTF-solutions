from pwn import *
from string import ascii_lowercase as s
from base64 import b64decode as bd

s += '_}'


def encrypt(payload):
    global io
    io.sendlineafter(b'flag: ', payload)
    return bd(io.recvline().decode())


known = b'gigem{'
io = remote("tamuctf.com", 443, ssl=True, sni="criminal")

while known[-1] != b'}'[0]:
    avg = len(encrypt(known+b'A')) - 1
    for c in s:
        payload = known + c.encode()
        print(payload.decode(), end='\r')
        if len(encrypt(payload)) == avg:
            known += c.encode()
            break
print(known)
