from pwn import remote, xor
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from Crypto.Cipher import AES
import json
from icecream import ic
ic.disable()
io = remote('integral-communication.chal.irisc.tf', 10103)

payload = json.dumps({"from": "guest", "act": "echo", "msg": ""}).encode()
intended = json.dumps({"from": "admin", "act": "flag", "msg": ""}).encode()
block1 = payload[:16]
block2 = payload[16:32]
int1 = intended[:16]
int2 = intended[16:32]
ic(block1, int1, block2, int2)

io.sendlineafter(b'> ', b'1')
io.sendlineafter(b': ', b'')
iv1 = bytes.fromhex(io.recvline().split()[-1].decode())
io.recvline()
ct1 = bytes.fromhex(io.recvline().split()[-1].decode())
_ct1 = xor(ct1, xor(block2, int2)+b'\x00'*32)
io.sendlineafter(b'> ', b'2')
io.sendlineafter(b': ', iv1.hex().encode())
io.sendlineafter(b': ', _ct1.hex().encode())
dec1 = bytes.fromhex(io.recvline().split(b': ')[-1].decode())
iv2 = xor(dec1[:16], int1, iv1)
io.sendlineafter(b'> ', b'2')
io.sendlineafter(b': ', iv2.hex().encode())
io.sendlineafter(b': ', _ct1.hex().encode())
flag = io.recvline().split(b': ')[-1].decode()
print(flag)