from Crypto.Cipher import AES
from Crypto.Hash import md5
from Crypto.Util.number import gcd
from binascii import hexlify as bfh

def get_vals():
    from pwn import remote
    io = remote('key-in-a-haystack.chal.uiuc.tf', 1337, ssl=True)
    ct = io.recvline().decode()
    prod = int(io.recvline().decode().split(': ')[1])
    return ct, prod

prods = [j for i,j in [get_vals() for _ in range(100)]]
ct, produ = get_vals()

for pro in prods:
    produ //= gcd(produ, pro)

key = md5(b"%d" % produ).digest()
AES.new(key, AES.MODE_ECB).decrypt(bfh('3ec904102d4b4e9446d19965ee1fb6f346232d1759e397ec36e4279613608893653a82b23326a460652802442d5ff455'))