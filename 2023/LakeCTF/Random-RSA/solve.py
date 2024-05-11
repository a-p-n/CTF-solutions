from pwn import remote
from Crypto.Util.number import long_to_bytes, isPrime
from mt19937predictor import MT19937Predictor

io = remote('chall.polygl0ts.ch', 9022)
predictor = MT19937Predictor()
count = 0
while count<20:
    x = io.recvline().decode().strip()
    if x.startswith("Sadly"):
        predictor.setrandbits(int(x.split()[1]), 1024)
        count += 1
    else:
        ct = int(x.split()[1])
        break

while True:
    x = io.recvline().decode().strip()
    if x.startswith("Cipher"):
        ct = int(x.split()[1])
        break

p = predictor.getrandbits(1024)
while not isPrime(p):
    p = predictor.getrandbits(1024)
q = predictor.getrandbits(1024)
while not isPrime(q):
    q = predictor.getrandbits(1024)
    
n = p*q
phi = (p-1)*(q-1)
e = 65537
d = pow(e,-1,phi)
m = pow(ct,d,n)
print(long_to_bytes(m))