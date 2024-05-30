from sage.all import *
from pwn import remote

con = remote("challenge.nahamcon.com", 32467)
con.recvuntil(b"Exit\n")
con.sendline(b"1")
con.sendlineafter(b"random N!\n> ", b"a")
con.recvline()
N1 = int(con.recvline()[2:].strip())
con.recvline()
c1 = int(con.recvline()[2:].strip())

con.recvuntil(b"Exit\n")
con.sendline(b"1")
con.sendlineafter(b"random N!\n> ", b"b")
con.recvline()
N2 = int(con.recvline()[2:].strip())
con.recvline()
c2 = int(con.recvline()[2:].strip())

print(discrete_log(N1, c1))