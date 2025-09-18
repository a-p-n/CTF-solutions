from Crypto.Util.number import *
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random

def getkey(x):
  h = SHA256.new()
  h.update(str(x).encode())
  return h.digest()

testcases=10
nbit=256

Ns=[]
Cs=[]
Ms=[]
ms=[]

for T in range(testcases):
  p=getPrime(nbit)
  q=getPrime(nbit)
  n=p*q

  m=random.randint(0,n-1)
  c=pow(m,2,n)

  R=random.sample(list(range(nbit*2-1)),k=4)
  eps=sum([pow(2,x) for x in R])

  M=m^^eps
  Ns.append(n)
  Cs.append(c)
  Ms.append(M)
  ms.append(m)
  

key=getkey(ms)

cipher=AES.new(key,AES.MODE_ECB)

flag=b"CTF{????????????????????????????????????????????????????????????????}"

enc=cipher.encrypt(pad(flag,16)).hex()

print(f"{Ns=}")
print(f"{Cs=}")
print(f"{Ms=}")
print(f"{enc=}")
