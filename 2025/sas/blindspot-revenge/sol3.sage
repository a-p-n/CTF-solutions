import hashlib

from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import Point, PointJacobi

from pwn import *
import json

# public parameters: secp256k1
Zq = GF(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)
E = EllipticCurve(Zq, [0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc, 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b])
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
p = E.order()
Zp = GF(p)

def send_json(conn, obj):
    conn.sendline(json.dumps(obj).encode())

def recv_json(conn):
    return json.loads(conn.recvline().decode())

def point2bytes(P):
    return P.to_bytes()

def random_oracle(Rp, m):
    RRp = PointJacobi.from_affine(Point(NIST256p.curve, int(Rp.xy()[0]), int(Rp.xy()[1])))

    if isinstance(m, str):
        m = m.encode()
    return Zp(
        int.from_bytes(hashlib.sha256(point2bytes(RRp) + m).digest(), byteorder="big")
    )

def verify(message, signature):
    R, s = signature
    c = random_oracle(R, message)
    assert G * s == X * c + R, "verification equation fails"
    return True

def inner_product(coefficients, values):
    return sum(y*x for x, y in zip(coefficients, values))

# adversary: open ‘ell‘ sessions
ell = 256
messages = [f"message{i}" for i in range(ell)] + ["forged message"]
conns = []

# server: generate commitments
#r = [Zp.random_element() for i in range(ell)]
#R = [G * r_i for r_i in r]
R = []
X = None

for i in range(ell):
    rem = remote("tcp.sasc.tf", 11770)
    rem.recvline()

    conns.append(rem)

    rem.send("sign")
    obj = recv_json(rem)

    R.append(E(obj["R"][0], obj["R"][1]))
    X = E(obj["Q"][0], obj["Q"][1])

print("R:", R)

# adversary: generate challenges
alpha = [[Zp.random_element(), Zp.random_element()] for i in range(ell)]
beta = [Zp.random_element() for i in range(ell)]
blinded_R = [[R[i] + G * alpha[i][b] + X * beta[i] for b in range(2)] for i in range(ell)]

c = [[random_oracle(blinded_R[i][b], messages[i]) for b in range(2)] for i in range(ell)]
P = ([-sum([Zp(2)^i * c[i][0]/(c[i][1] - c[i][0]) for i in range(ell)])] + [Zp(2)^i / (c[i][1] - c[i][0]) for i in range(ell)])

c_to_decompose = random_oracle(inner_product(P[1:], R), messages[ell])
bits = [int(b) for b in bin(c_to_decompose - inner_product(P[1:], beta) + P[0])[2:].rjust(256, "0")][::-1]
blinded_c = [int(c[i][b] + beta[i]) for (i, b) in enumerate(bits)]

s = []

# server: generate the responses
for i in range(ell):
    send_json(conns[i], {"c": blinded_c[i]})
    obj = recv_json(conns[i])
    s.append(obj["s"])

print(s)
#s = [blinded_c[i]*x + r[i] for i in range(ell)]

# attacker: generate the forged signatures
forged_signatures = [(blinded_R[i][bits[i]], s[i] + alpha[i][bits[i]]) for i in range(ell)]
forged_signatures += [(inner_product(P[1:], R), inner_product(P[1:], s))]

for i in range(ell+1):
    rem = remote("tcp.sasc.tf", 11770)
    rem.recvline()

    rem.send("verify")
    print("ro:", forged_signatures[i][0], random_oracle(forged_signatures[i][0], "a"))
    send_json(rem, {"msg": messages[i], "sig": [[int(forged_signatures[i][0][0]), int(forged_signatures[i][0][1])], int(forged_signatures[i][1])]})
    print(rem.recvline())
    
    if i == ell:
        print(rem.recvline())

# check all previous signatures were valid
#print(all([verify(messages[i], forged_signatures[i]) for i in range(ell+1)]))