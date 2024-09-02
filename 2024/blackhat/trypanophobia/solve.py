from pwn import remote
from sage.all import *
from Crypto.Util.number import getPrime, inverse
import json

io = remote("54.78.163.105", 30633)

p, q = getPrime(1024), getPrime(1024)

io.sendlineafter(b' > ', b'A')
io.sendlineafter(b'> (JSON) ', json.dumps({'p': p, 'q': q}).encode())

io.sendlineafter(b' > ', b'E')
ct1 = eval(io.recvline().decode().split()[-1])

io.sendlineafter(b' > ', b'A')
io.sendlineafter(b'> (JSON) ', json.dumps({'p': p, 'q': q}).encode())

io.sendlineafter(b' > ', b'E')
ct2 = eval(io.recvline().decode().split()[-1])

F = GF(p)
c1 = F(ct1)
c2 = F(ct2)

d = inverse(0x10001, p-1)

y_mul = c2/c1
y8 = y_mul ** d
print(y8)
# y_list = [y for y4 in sqrt(y8, all=True) for y2 in sqrt(y4,all=True) for y in sqrt(y2, all=True)]
y_list = []
for y4 in sqrt(y8, all=True):
    try:
        for y2 in sqrt(y4,all=True):
            try:
                for y in sqrt(y2, all=True):
                    y_list.append(y)
            except:
                continue
    except:
        continue

for y in y_list:
    if int(y).bit_length() <= 256:
        print(y)
        break
y = F(min(y_list))

cfin = pow(c1, d, p) * inverse(y^15, p)
print(bytes.fromhex(hex(cfin)[2:]))