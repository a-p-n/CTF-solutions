from Crypto.Util.number import *

P = 2
N = 150
F, k = GF(2**8), 14
z8 = F.gens()[0]

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return rows

G = Matrix(F, load_matrix("/home/apn/Documents/bi0s/my_git/bi0s/ctf/mapna/glnq/generator.txt"))
A_pub = Matrix(F, load_matrix("/home/apn/Documents/bi0s/my_git/bi0s/ctf/mapna/glnq/alice.pub"))
H = Matrix(F, load_matrix("/home/apn/Documents/bi0s/my_git/bi0s/ctf/mapna/glnq/bob.pub"))

r = 79229371458530696292133175295

def babystep_giantstep(g, y, p):
    m = int((p-1)**0.5 + 0.5)
    table = {}
    gr = 1
    for r in range(m):
        table[str(gr)] = r
        gr = gr * g
    gm = g^(-m)
    ygqm = y            
    for q in range(m):
        if str(ygqm) in table:
            return q * m + table[str(ygqm)]
        ygqm = ygqm * gm
    return None

def Pohlig_Hellman_DLP(P,sP,order):
    primes = []
    for i,k in factor(order):
        primes.append(i^k)
    dlogs = []
    for fac in primes:
        t = int(order) // int(fac)
        dlog = babystep_giantstep(P^t, sP^t, fac)
        assert  (P^t)^dlog == sP^t
        dlogs += [dlog]
        print("factor: "+str(fac)+", Discrete Log: "+str(dlog))
    return crt(dlogs, primes )


flag = int(Pohlig_Hellman_DLP(G,H,r))
assert G^flag == H
print(flag)