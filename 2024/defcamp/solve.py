from pwn import *
import sys
context.log_level = 'debug'
conn = remote('35.246.234.196',30863)
f = open('./ctr.txt','r').readlines()
l = len(f)
ltry = 100
cts = []
for line in f:
    cts.append(bytes.fromhex(line.strip()))

pt = b'a'*16
ctrs = []

for _ in range(ltry):
    conn.recvuntil(b'Give me no more than 16 bs\n')
    conn.sendline(pt)
    ctrs.append(bytes.fromhex(conn.recvline().split()[-1].decode()))

found = 0
arrange = {}
flag = ''
for i in range(l):
    for j in range(ltry):
        try:
            print(xor(xor(ctrs[j],pt),cts[i]).decode())
            print(f'ct {i} -> counter {j}')
            flag += chr(j+1)
            arrange[i+1] = xor(xor(ctrs[j],pt),cts[i]).decode()
            found += 1
            break
        except:
            pass
print("FOUND:",found)
print(flag)