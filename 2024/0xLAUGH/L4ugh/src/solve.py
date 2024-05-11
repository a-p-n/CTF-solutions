from pwn import remote, xor
from json import dumps
from sage.all import *

def s(x):
    io.sendline(dumps(x).encode())

io = remote("20.55.48.101", "1337")

io.read().decode()
s({"option":"1"})
exec(io.readline().decode())
exec(io.readline().decode())
e1, e2, _ = es
n1, n2, _ = Ns
B = Matrix([
    [1,  e1 ,  e2 ],
    [0,  n1 ,  0  ],
    [0,  0  ,  n2 ],
])
W = diagonal_matrix([2**512, 1, 1])
B = (B*W).LLL()/W
d_high = B[0][0]

s({"option":"2"})
io.read().decode()
io.sendline(f"{2**333-1}".encode())
exec(io.readline().decode().split("\t")[1])
d_low = RAND[0] // (2**333-1)
d = d_high * 2**333 + d_low


def initial_part():
    io.read()
    s({"option":"3", "d":str(d)})
    io.recvuntil(b"sign in")

initial_part()
s({"option":"1","user":"admin"})
pt=io.recvline().decode().strip()
token=bytes.fromhex(io.recvline().decode().strip())
iv, ct = token[:16], token[16:]
ct =ct[:10]+ xor(ct[10:15], b"true ", b"false") + ct[15:]
initial_part()
s({"option":"2","token":(iv+ct).hex()})
error_msg=io.recvline().decode().strip()
kk=eval(error_msg[17:])
new_iv = xor(kk[:16], iv,pt[:16].replace("'",'"').encode())
initial_part()
s({"option":"2","token":(new_iv+ct).hex()})
s({"option":"1"})
print(io.read().decode())
print(io.read().decode())

# 0xL4ugh{cryptocats_B3b0_4nd_M1ndfl4y3r}