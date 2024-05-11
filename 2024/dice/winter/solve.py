from pwn import remote
from hashlib import sha256
import os
from tqdm import tqdm

msg = os.urandom(32)
for _ in tqdm(range(2**32)):
	m = sha256(msg).digest()
	for n in m:
		if n >= 128:
			break
	else:
		print('low', msg.hex())
		low = msg.hex()
	for n in m:
		if n <= 128:
			break
	else:
		high = msg.hex()
		print('high', msg.hex())
	msg = m

def hash(x, n):
	for _ in range(n):
		x = sha256(x).digest()
	return x

r = remote('mc.ax', 31001)
r.sendlineafter(b"give me a message (hex): ", low.encode())
r.recvuntil(b': ')
sig1 = bytes.fromhex(r.recvline().decode())
m1 = hash(bytes.fromhex(low), 1)
m2 = hash(bytes.fromhex(high), 1)
chunks = [sig1[i:i+32] for i in range(0, len(sig1), 32)]
sig2 = b''.join([hash(x, n2 - n1) for x, n1, n2 in zip(chunks, m1, m2)])
r.sendlineafter(b': ', low.encode())
r.sendlineafter(b': ', sig2.hex().encode())
r.interactive()