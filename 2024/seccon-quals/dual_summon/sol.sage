import os
os.environ['TERM'] = 'xterm-256color' 
from pwn import remote
con = remote("dual-summon.seccon.games", 2222)
from Crypto.Util.number import bytes_to_long, long_to_bytes
BF.<X> = GF(2)[]
FF.<A> = GF(2 ^ 128, modulus=X ^ 128 + X ^ 7 + X ^ 2 + X + 1)

def int2ele(integer):
    res = 0
    for i in range(128):
        res += (integer & 1) * (A ^ (127 - i))
        integer >>= 1
    return res

def bytes2ele(b):
    return int2ele(bytes_to_long(b))

def ele2int(element):
    integer = element.integer_representation()
    res = 0
    for i in range(128):
        res = (res << 1) + (integer & 1)
        integer >>= 1
    return res

def ele2bytes(ele):
    return long_to_bytes(ele2int(ele))

con.recvline()
con.sendlineafter(b"dual summon >", b"1")
con.sendlineafter(b"(1 or 2) >", b"1")
con.sendlineafter(b"name of sacrifice (hex) >", ("0"*32).encode())
con.recvline()
tag1_1 = con.recvline().decode().split(" = ")[1].strip()

con.sendlineafter(b"dual summon >", b"1")
con.sendlineafter(b"(1 or 2) >", b"1")
con.sendlineafter(b"name of sacrifice (hex) >", ("1"*32).encode())
con.recvline()
tag1_2 = con.recvline().decode().split(" = ")[1].strip()

con.sendlineafter(b"dual summon >", b"1")
con.sendlineafter(b"(1 or 2) >", b"2")
con.sendlineafter(b"name of sacrifice (hex) >", ("0"*32).encode())
con.recvline()
tag2_1 = con.recvline().decode().split(" = ")[1].strip()

con.sendlineafter(b"dual summon >", b"1")
con.sendlineafter(b"(1 or 2) >", b"2")
con.sendlineafter(b"name of sacrifice (hex) >", ("1"*32).encode())
con.recvline()
tag2_2 = con.recvline().decode().split(" = ")[1].strip()

v = bytes2ele(bytes.fromhex("1"*32))

tag1_1 = bytes2ele(bytes.fromhex(tag1_1))
tag1_2 = bytes2ele(bytes.fromhex(tag1_2))
h1sqr = (tag1_1 - tag1_2) / (v)

tag2_1 = bytes2ele(bytes.fromhex(tag2_1))
tag2_2 = bytes2ele(bytes.fromhex(tag2_2))
h2sqr = (tag2_1 - tag2_2) / (v)

p = (tag2_1 - tag1_1)/(h1sqr - h2sqr)
p = ele2bytes(p)
con.sendlineafter(b"dual summon >", b"2")
con.sendlineafter(b"name of sacrifice (hex) >", p.hex().encode())
con.interactive()


