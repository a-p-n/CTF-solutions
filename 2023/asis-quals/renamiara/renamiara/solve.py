from pwn import *

border = b"|\n"+b"|"*72+b'\n'
con = connect("45.153.241.194","31337")

con.sendafter(border,b"y\n")

for i in range(40):
    con.recvuntil(b'p = ')
    p = int(con.recvuntil(b'\n')[:-1].decode('utf-8'))
    g = p-4
    con.sendafter(b"First send the base g: \n",str(g).encode()+b"\n")
    x,y = 2,p-2
    assert pow(g,x+y,p) == (x*y)%p
    con.sendafter(b"Send the solutions for pow(g, x + y, p) = x * y, as x and y:\n",str(x).encode()+b","+str(y).encode()+b"\n")
    if i == 39:
        print(con.recvline())
        quit()
    con.recvline()