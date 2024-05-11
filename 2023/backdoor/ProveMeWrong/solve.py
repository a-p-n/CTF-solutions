from sage.all import *
from pwn import *
from Crypto.Util.number import *
from base64 import *
from sage.groups.generic import bsgs

q = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
E = EllipticCurve(GF(q), [0, 4])
s = 2**252//(2**36-1)

# these are just a reimplementation of serialize_compressed and deserialize_compressed

def dec(bs):
    return sorted(E.lift_x(ZZ(bytes_to_long(bs) % 2**381), all=True))[bs[0] & 0x20 == 0x20]

def enc(p):
    x, y, _ = vector(ZZ, p)
    x += (5 if y > q // 2 else 4) << 381
    return long_to_bytes(x)

io = remote('34.70.212.151', 8009)
io.sendline(str(s).encode())
io.readline_contains(b'Key')
tmp = b64decode(io.readline())

G = dec(tmp[8:56])
Gβ = dec(tmp[56:104])
print('Computing β...')
β = s * bsgs(G*s, Gβ, (0, ZZ(2**36)), operation='+')
print(f'{β = }')

io.sendline(b'1')
proof = mod((β**2-177013)/(β-1), r).lift()*G
io.sendline(b64encode(enc(proof)))
print(io.readall().decode())
