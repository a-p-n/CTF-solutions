from pwn import *
from sage.all import *

io = remote("tamuctf.com", 443, ssl=True, sni="pcg")

m = eval(io.recvline())
F = Zmod(m)
P = PolynomialRing(F, 'x')
x = P.gen()

vals = []
for _ in range(256*3):
    vals.append(eval(io.recvline().decode()))

points = [(vals[i], vals[i+1]) for i in range(len(vals)-1)]
target_pol = P.lagrange_polynomial(points)

newvals = [vals[-1]]
for i in range(128):
    newvals.append(target_pol(newvals[-1]))

for val in newvals[1:]:
    io.sendline(str(val).encode())
io.interactive()
