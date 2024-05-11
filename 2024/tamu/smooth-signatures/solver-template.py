from pwn import *
from hashlib import sha256
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sage.all import factor, gcd, lcm

io = remote("tamuctf.com", 443, ssl=True, sni="smooth-signatures")
io.recvuntil(f"Your verification exponent e = ")
e = int(io.recvline().strip())
msg1 = b"hello"
h1 = bytes_to_long(sha256(msg1).digest())
io.recvuntil(f"Give the oracle a message to sign: ")
io.sendline(msg1)
io.recvuntil(f"Your verification signature is (")
sig1 = io.recvuntil(")").strip().split(b", ")
r1 = int(sig1[0])
s1 = int(sig1[1][:-1])
print(f"{r1 = }, {s1 = },{h1 = }")

msg2 = b"gyat is the flag?"
h2 = bytes_to_long(sha256(msg2).digest())
io.recvuntil("Give the oracle another message to sign: ")
io.sendline(msg2)
io.recvuntil(f"Your second verification signature is (")
sig2 = io.recvuntil(")").strip().split(b", ")
r2 = int(sig2[0])
s2 = int(sig2[1][:-1])

print(f"{r2 = }, {s2 = },{h2 = }")

p1 = r1 ^ e
p2 = s1 ^ e
p3 = r2 ^ e
p4 = s2 ^ e
n = gcd(p2-p1-h1, p4-p3-h2)

print(f"{n = }")

factors = list(factor(n))
q = 1
for p in factors:
    q = lcm(q, p[0]-1)
d = pow(e, -1, q)

r3, s3 = sign(n, b"What is the flag?", d)

io.recvuntil("Ask the oracle a question: ")
io.sendline(b"What is the flag?")
io.recvuntil("Give the verification signature: ")
io.sendline(f"{r3},{s3}")

io.interactive(prompt="")
