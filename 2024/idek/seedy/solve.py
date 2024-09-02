from sage.all import (Matrix, GF)
import random
import tqdm

setstate = lambda bmap: random.setstate((3, (*[int(bmap>>(i*32)&((1<<32)-1)) for i in range(624)], 624), None))

output = [int(i) for i in open("./seedy/attachments/output.txt","r").read()[:-1]]
chrs = list(set(output))
inds = {i:output.index(i) for i in chrs}
bits = 5

M = Matrix(GF(2),19968,len(output)*bits)
for i in tqdm.trange(19968):
    setstate(1<<i)
    M[i] = [i>>j&1 for i in random.choices([*range(32)], k=len(output)) for j in range(bits)]

M = M.T

print("Constructing piS")
piS = Matrix(GF(2),(len(output)-len(inds))*bits,len(output)*bits)
j=0
for i in tqdm.trange(len(output)):
  if i in inds.values(): continue
  for b in range(bits):
    piS[j,inds[output[i]]*bits+b]=-1
    piS[j,i*bits+b]=1
    j+=1

print("Constructing kernel")
SM = piS*M
ker = SM.right_kernel()
for v in ker.basis():
    if sum(int(j) for j in v)>100: # nontrivial element, alternatively can check if Mv=0
        randstate = v
        break
x = sum(int(i)*(1<<n) for n,i in enumerate(randstate))
setstate(x)
shuf = ''.join(map(str, [random.getrandbits(int(1.337)) for _ in range(int(1337**1.337 * 1.337))]))
assert shuf == ''.join(map(str, output))
chrmap = {i:output[shuf.index(i)] for i in chrs}
print(f"EPFL{{{''.join(chrmap[i] for i in chrs)}}}")