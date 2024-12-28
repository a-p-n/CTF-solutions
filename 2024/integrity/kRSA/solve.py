from pwn import remote

e = 65537
r = remote('krsa.ctf.intigriti.io', 1346)
r.recvline()
r.recvuntil(b'n=')
n = (int(r.recvline().strip()))
r.recvuntil(b'e=')
r.recvline()
r.close()