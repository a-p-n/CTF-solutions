from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *

io = remote("ctf.tcp1p.com", 35257)

io.recvuntil(b"Alice: My message")
enc_flag = bytes.fromhex(io.recvline().strip().decode())
txt = b"TCP1P{"
io.sendlineafter(b">> ", txt)
io.recvuntil(b"Steve: ")
ct = bytes.fromhex(io.recvline().strip().decode())

res = {}
for a in range(999999,-1,-1):
    key1 = ((str(a).zfill(6)*4)[:16]).encode()
    c1 = AES.new(key=key1, mode=AES.MODE_ECB).encrypt(pad(txt,16))
    res[c1] = key1

for b in range(999999,-1,-1):
    key2 = ((str(b).zfill(6)*4)[:16]).encode()
    c2 = AES.new(key=key2, mode=AES.MODE_ECB).decrypt(ct)
    if c2 in res:
        key1 = res[c2]
        print(key1,key2)
        break

print(AES.new(key1, AES.MODE_ECB).decrypt(AES.new(key2, AES.MODE_ECB).decrypt(enc_flag)))