from pwn import remote
import json
import hashlib
from ntt import NTTDomain

n, q, w, p = 1024, 12289, 4324, 9389
ntt = NTTDomain(q, w, p)
def HashBall( m: bytes, tau: int) -> list:
    """ Deterministically generates sparse polynomials with weight tau. """
    if isinstance(m, str):
        m = m.encode()
    h = hashlib.sha256(m).digest()
    c = n * [0]
    for i in range(n - tau, n):
        hi = int(hashlib.sha256(h + i.to_bytes(2, 'big')).hexdigest(), 16)
        hi //= i; j = hi % i; hi //= i
        hi //= 2; k = hi % 2; hi //= 2
        c[i] = c[j]
        c[j] = (1 - 2 * k) % q
    return c

conn = remote('', '')
conn.recvuntil(b'Public = ')
pub = json.loads(conn.recvline())

conn.recvuntil(b"[Q]uit\n|\n")
conn.sendlineafter(b"|  > ", b"s")

conn.sendlineafter(b"|  > (str) ", b"hi")
conn.recvuntil(b"Sig = ")
sig = json.loads(conn.recvline())

C = ntt.fromPoly(HashBall("hi" + int(sig['r'], 16), 38))
P = int(pub['E'], 16) * int(sig['V'], 16) - int(pub['A'], 16) * C + int(sig['W'], 16)
Y1 = P // int(pub['A'], 16)
Y2 = P % int(pub['A'], 16)
U = Y1 + C
D = (int(sig['W'], 16) - Y2) // U

conn.recvuntil(b"[Q]uit\n|\n")
conn.sendlineafter(b"|  > ", b"c")

conn.sendlineafter(b"|  > (hex) ", hex(D)[2:])
conn.recvall()
conn.close()