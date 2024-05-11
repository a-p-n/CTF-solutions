from sage.all import *
from pwn import remote
from tqdm import trange

io = remote("gold.b01le.rs", int(5001))

print(io.recvline().decode())
print(io.recvline().decode())
print(io.recvline().decode())
print(io.recvline().decode())


def send_len(x): return io.sendlineafter(b"primes> ", str(x).encode())


def recv_params():
    n = int(io.recvline().decode().split(" = ")[-1].strip(), 16)
    e = int(io.recvline().decode().split(" = ")[-1].strip(), 16)
    c = int(io.recvline().decode().split(" = ")[-1].strip(), 16)

    return n, e, c


nlist = []
elist = []
clist = []
plist = []
for i in trange(4096 // 128):
    send_len(64)
    n, e, c = recv_params()
    (p, _), (q, _) = list(factor(n))
    d = inverse_mod(e, (p-1) * (q-1))
    plist.append(int(pow(c, d, n)))
    nlist.append(int(n))
    clist.append(int(c))

res = crt(plist, nlist)

print(bytes.fromhex(hex(res)[2:])[200:251].decode())