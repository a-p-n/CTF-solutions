from sage.all import *
from pwn import remote
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
E = EllipticCurve(GF(p), [a,b])
io = remote('chall.polygl0ts.ch', int(9025))
for i in range(3):
    io.recvline()
pub = E(eval(io.recvline().decode().split()[-1]))
print(pub)
lb = 48
ub = 49
P_list = []
pi_list = []
sk_list = []
for i in range(4):
    while True:
        b_ = randint(0,p-1)
        E_ = EllipticCurve(GF(p), [a,b_])
        factors = [f for f,_ in factor(E_.order())]
        if any(f.nbits()>=lb and f.nbits()<=ub for f in factors):
            break
    pi = factors[0]
    for f in factors:
        if f.nbits()>=lb and f.nbits()<=ub and f>pi:
            pi = f
    P = E_.random_point() * (E_.order()//pi)
    assert P.order()==pi
    P_list.append(P)
    pi_list.append(pi)
    io.sendlineafter(b'x : \n', str(P.xy()[0]).encode())
    io.sendlineafter(b'y : \n', str(P.xy()[1]).encode())
    io.recvline()
    sk = E_(eval(io.recvline().decode().strip()))
    sk_list.append(sk)
    print(sk)
    
print(P_list)
print(pi_list)
logs = []
for i in range(4):
    dlog = P_list[i].discrete_log(sk_list[i])
    print(dlog)
    logs.append(dlog)
    
PK = crt(logs, pi_list)
print(PK)
print(prod(pi_list))
flag_point = inverse_mod(PK, E.order())*pub
print(flag_point.xy()[0])