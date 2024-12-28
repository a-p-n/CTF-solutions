from pwn import *

HOST = 'chall.polygl0ts.ch'
PORT = 9001

while True:
    io = remote(HOST,PORT)
    flag = 0
    io.recvline()
    pay = b'42'
    for t in range(4):
        io.recvline()
        io.sendline(pay)
        r = io.recvline().decode().strip()
        print(r)
        if r!="it's valid":
            
            break
        else:
            print(r)
            flag = 1
    if flag:
        break

io.interactive()