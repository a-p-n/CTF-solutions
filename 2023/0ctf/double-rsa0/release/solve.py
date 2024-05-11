from pwn import *
import itertools

r = remote('chall.ctf.0ops.sjtu.cn', 32226)

r.recvuntil(b'sha256(XXXX + ')
proof = r.recv(16)
digest = r.recv(69)[5:]
print(proof,digest)
characters = string.ascii_letters + string.digits

combinations = itertools.product(characters, repeat=4)
for combo in combinations:
    password = ''.join(combo)
    if hashlib.sha256(password.encode() + proof).hexdigest() == digest.decode():
        print(password)
        break

print(r.sendlineafter(b"Give me XXXX:", password.encode()))
r.interactive()