from pwn import *
import json
from sage.all import *
from Crypto.Util.number import long_to_bytes

con = connect("54.78.163.105",30646)

with open("/home/apn/Downloads/ctf/primes.txt","r") as f:
    primes = f.readlines()
    for i in range(len(primes)):
        primes[i] = int(primes[i][:-1])


def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

con.recvline()
con.recvline()

f0 = int(con.recvline()[len("|    0: 0x"):],16)
f1 = int(con.recvline()[len("|    0: 0x"):],16)
f2 = int(con.recvline()[len("|    0: 0x"):],16)
f3 = int(con.recvline()[len("|    0: 0x"):],16)
f4 = int(con.recvline()[len("|    0: 0x"):],16)
f5 = int(con.recvline()[len("|    0: 0x"):],16)

Cs = [f0,f1,f2,f3,f4,f5]

F0 = int.from_bytes(b"BHFlagY",'big')

mods = []
for p in primes:
    if 2^F0 == Mod(f0,p):
        print(p)
        mods.append(p)
        

M = prod(mods)
parts = []
for c in Cs:
    parts.append(discrete_log(c,2))

b"".join(long_to_bytes(_) for _ in parts)
