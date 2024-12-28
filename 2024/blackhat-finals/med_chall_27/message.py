from pwn import remote
import os, json, hashlib
from secrets import randbelow
from typing import List, Tuple

# Non-native dependencies
from Crypto.Util.number import getPrime, inverse, isPrime, GCD  

class FiatSchnorr:
    def __init__(self, pbit: int, qbit: int) -> None:
        self.p, self.q = self.SafePrimeGen(pbit, qbit)
        while True:
            self.g = pow(2, (self.p - 1) // self.q, self.p)
            if pow(self.g, self.q, self.p) == 1:
                break
        self.sk = [randbelow(self.q) for _ in '01']
        self.pk = [pow(self.g, i, self.p) for i in self.sk]
        
    def __repr__(self) -> str:
        return json.dumps({
            'p' : '0x' + self.Int2Byte(self.p).hex(),
            'q' : '0x' + self.Int2Byte(self.q).hex(),
            'g' : '0x' + self.Int2Byte(self.g).hex()
        })
    
    def Int2Byte(self, x: int) -> bytes:
        return x.to_bytes(-(-len(bin(x)[2:]) // 8), 'big')
    
    def Hash(self, lst: List[int]) -> int:
        return int.from_bytes(HASH(b''.join([self.Int2Byte(i) for i in lst])).digest(), 'big')
        
    def SafePrimeGen(self, pbit: int, qbit: int) -> Tuple[int, int]:
        while True:
            q = getPrime(qbit)
            for k in range(256):
                r = getPrime(pbit - qbit - 1)
                p = (2 * q * r) + 1
                if len(bin(p)[2:]) != pbit:
                    continue
                if isPrime(p):
                    return p, q
                
    def Encode(self, x: Tuple[int]) -> bytes:
        y = [self.Int2Byte(i) for i in x]
        z = [len(i).to_bytes(2, 'big') + i for i in y]
        return b"".join(z)
    
    def Decode(self, x: bytes) -> Tuple[int]:
        y = []
        while x:
            l  = int.from_bytes(x[:2], 'big')
            y += [int.from_bytes(x[2:l+2], 'big')]
            x  = x[l+2:]
        return tuple(y)
        
    def Encrypt(self, m: bytes) -> bytes:
        r, s = [randbelow(self.q) for _ in '01']
        A = pow(self.g, r, self.p)
        B = pow(self.g, s, self.p)
        C = (pow(self.pk[0], r, self.p) * int.from_bytes(m, 'big')) % self.p
        D = (pow(self.pk[1], s, self.p) * int.from_bytes(m, 'big')) % self.p
        u, v = [randbelow(self.q) for _ in '01']
        E = pow(self.g, u, self.p)
        F = pow(self.g, v, self.p)
        G = (pow(self.pk[0], u, self.p) * inverse(pow(self.pk[1], v, self.p), self.p)) % self.p
        t = self.Hash([E, F, G])
        H = (u + t * r) % self.q
        I = (v + t * s) % self.q
        return self.Encode((A, B, C, D, E, F, G, H, I))
    
    def Decrypt(self, ct: bytes) -> bytes:
        try:
            A, B, C, D, E, F, G, H, I = self.Decode(ct)
            t = self.Hash([E, F, G])
            assert pow(self.g, H, self.p) == (E * pow(A, t, self.p)) % self.p
            assert pow(self.g, I, self.p) == (F * pow(B, t, self.p)) % self.p
            assert (pow(self.pk[0], H, self.p) * inverse(pow(self.pk[1], I, self.p), self.p)) % self.p == (G * pow(C * inverse(D, self.p), t, self.p)) % self.p
            return self.Int2Byte((C * inverse(pow(A, self.sk[0], self.p), self.p)) % self.p)
        except:
            return b""
       
 
io = remote('localhost', 1234)
io.recvuntil(b'FIAT = ')
params = json.loads(io.recvline().decode())
p = eval(params['p'])
g = eval(params['g'])
q = eval(params['q'])
print(params)
obj = FiatSchnorr(1024, 1012)
payload1 = obj.Encode((1,1, l2b(b'FLAG[:1]'), l2b(b'FLAG[:1]'), 1, 1, 1, 0, 0))
io.sendline(b'E')
io.sendline(payload1.hex().encode())
io.recvuntil(b'RESP = ')
ct1 = bfh(io.recvline().strip().decode())
A1, B1, C1, D1, E1, F1, G1, H1, I1 = obj.Decode(ct1)
gskore = (inverse(int.from_bytes(b'B', 'big'), p) * C1 ) % p
print(gskore)
payload2 = obj.Encode((1,1, l2b(b'FLAG'), l2b(b'FLAG'), 1, 1, 1, 0, 0))
io.sendline(b'E')
io.sendline(payload2.hex().encode())
io.recvuntil(b'RESP = ')
ct2 = bfh(io.recvline().strip().decode())
A2, B2, C2, D2, E2, F2, G2, H2, I2 = obj.Decode(ct2)
# flag = C2 * 