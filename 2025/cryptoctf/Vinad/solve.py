#!/usr/bin/env python3

from Crypto.Util.number import *
from tqdm import tqdm

# Paste contents of output.txt here
with open("output.txt") as f:
    data = f.read()

# Extract R, n, c from the output
with open("output.txt", "r") as f1:
    x = f1.readlines()

R = eval(x[0][4:])
n = eval(x[1][4:])
c = eval(x[2][4:])
nbit = len(R)
print(n)
# Compute vinad(x, R)
def parinad(n):
    return bin(n).count('1') % 2

def vinad(x, R):
    return int(''.join(str(parinad(x ^ r)) for r in R), 2)

# Precompute vinad(0x10001, R)
V = vinad(0x10001, R)

print("[*] Starting brute-force for p...")

# Try possible p values from 2^510 to 2^512
# You can use smaller range in testing, e.g., 2^20 values
for candidate in tqdm(range(2**20, 2**22)):
    p = candidate
    e = p ^ V

    if p == 0 or e == 0:
        continue
    if n % p != 0:
        continue

    q = n // p
    phi = (p - 1) * (q - 1)

    if GCD(e, phi) != 1:
        continue

    d = inverse(e, phi)

    # Decrypt
    m_sumR = pow(c, d, n)
    m = m_sumR - sum(R)
    
    try:
        flag = long_to_bytes(m)
        if b"N0PS" in flag or b"CTF" in flag or b"{" in flag:
            print(f"[+] Success! Flag: {flag.decode()}")
            break
    except:
        continue
else:
    print("[-] Failed to find correct p.")
