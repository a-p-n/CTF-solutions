from pwn import remote
from Crypto.Util.number import *
import subprocess
from math import gcd
from Crypto.Util.number import long_to_bytes as l2b

io = remote('chal.amt.rs', 1417)
io.recvuntil(b'proof of work:\n')
cmd = io.recvline().strip().decode()
output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
io.sendlineafter(b'solution: ', output.strip())

enc_flag = eval(io.recvline().decode().split(' = ')[-1])

vals = [getPrime(513) for _ in range(4)]
A = vals[0]*vals[1]
B = vals[2]*vals[3]
C = vals[0]*vals[3]
D = vals[1]*vals[2]
cts = []
for x in [A, B, C, D]:
    io.sendlineafter(b'message? ', str(x).encode())
    print('gyatt')
    cts.append(int(io.recvline().decode(), 16))

kn1 = cts[0]*cts[1] - cts[2]*cts[3]

vals = [getPrime(513) for _ in range(4)]
A = vals[0]*vals[1]
B = vals[2]*vals[3]
C = vals[0]*vals[3]
D = vals[1]*vals[2]
cts = []
for x in [A, B, C, D]:
    io.sendlineafter(b'message? ', str(x).encode())
    print("got")
    cts.append(int(io.recvline().decode(), 16))

kn2 = cts[0]*cts[1] - cts[2]*cts[3]

n = gcd(kn1, kn2)
blind_val = getPrime(1025)
io.sendlineafter(b'message? ', str(blind_val).encode())
enc_blind = int(io.recvline().decode(), 16)
io.sendlineafter(b'message? ', str((enc_flag*blind_val) % n).encode())
blinded_flag = int(io.recvline().decode(), 16)
flag = (inverse(enc_blind, n) * blinded_flag) % n
print(l2b(flag))
