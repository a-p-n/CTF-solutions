import os
import gmpy2
import Crypto.Util.number as number
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def gen_params():
    e = gmpy2.mpz(number.getPrime(520))
    while True:
        while True:
            p = gmpy2.mpz(number.getPrime(512))
            q = (p * gmpy2.invert(p - 1, e)) % e
            if q.is_prime():
                break

        n = p * q
        phi = (p-1)*(q-1)

        if gmpy2.gcd(e, phi) == 1 and e < phi:
            d = (1 + (e - 1) * phi) // e
            return (int(n), int(e), int(d))
        
flag = os.environ["FLAG"]
key = RSA.construct(gen_params())

cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(flag.encode())

print("Flag:", ciphertext.hex())
print("n:", key.n)
print("e:", key.e)