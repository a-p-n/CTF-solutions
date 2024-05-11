from pwn import remote
from math import ceil

io = remote('0.cloud.chals.io', 19554)
for i in range(6):
    io.recvline()

privates = [list() for i in range(50)]
for i in range(100):
    print(i,end='\r')
    io.sendlineafter(b': ', b'1')
    shares = []
    io.recvline()
    for j in range(50):
        shares.append(eval(io.recvline().strip().split(b':')[1]))
    for j in range(50):
        x = min(shares[j])
        privates[j].append(abs(ceil(x)//48))
    io.recvline()

PRIV = [sum(privates[i])//100 for i in range(50)]
io.sendlineafter(b': ', b'2')
io.sendlineafter(b': ', ' '.join(map(str, PRIV)).encode())
io.interactive()