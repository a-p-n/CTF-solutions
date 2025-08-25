from sage.all import *
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
import os

def main():
    # Given values
    e = 65537
    k = 16
    with open('./MRSA/output.txt') as f:
        C = matrix(ZZ, k, k, eval(f.readline().strip().split('=')[1].strip()))
        ct = eval(f.readline().strip().split('=')[1].strip())

    # Compute determinant D of C
    D = det(C)

    # Assume det(M) = 1, so n divides (D - 1)
    n_candidate = D - 1

    # Factor n_candidate to find n (which is the product of two 1024-bit primes)
    # In practice, use a factorization algorithm to find p and q
    p = factor(n_candidate)[0][0]  # Replace with actual prime factor
    q = factor(n_candidate)[1][0]  # Replace with actual prime factor
    n = p * q

    # Now compute M modulo p and modulo q
    C_p = matrix(GF(p), k, k, C_list)
    C_q = matrix(GF(q), k, k, C_list)

    # Compute e-th root modulo p and q
    M_p = C_p ** (1/e)
    M_q = C_q ** (1/e)

    # Combine using CRT
    M = matrix(ZZ, k, k)
    for i in range(k):
        for j in range(k):
            a = M_p[i][j].lift()
            b = M_q[i][j].lift()
            M[i, j] = crt([a, b], [p, q])

    # Convert M to bytes
    key_bytes = bytes([M[i][j] for i in range(k) for j in range(k)])

    # Extract AES key and nonce
    aes_key = key_bytes[:32]
    nonce = key_bytes[-8:]

    # Decrypt
    aes = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    flag = aes.decrypt(ct)
    print(flag)

if __name__ == '__main__':
    main()