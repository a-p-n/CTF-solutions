from pwn import *
from math import gcd

def extract_hex(resp):
    lines = resp.split('\n')
    for line in lines:
        if '~~~' in line and line.startswith('|   ~~~ '):
            clean_line = line.replace('~~~', '').strip()
            parts = clean_line.split()
            for part in parts:
                if all(c in '0123456789abcdefABCDEF' for c in part) and len(part) > 16:
                    return part
    return None

def interact_with_remote(num_requests=5):
    host = '34.252.33.37'
    port = 31662
    ciphertexts = []
    
    conn = remote(host, port)
    for _ in range(num_requests):
        conn.recvuntil(b'> ')
        conn.sendline(b's')
        for __ in range(6): conn.recvline()
        resp = conn.recvline().decode()
        ciphertexts.append(extract_hex(resp))

    return ciphertexts

m = 1 << 64
prefix = b'BHFlagY{'
p_len = 41
steps = 6

cs = interact_with_remote(7)

y = []
msbs = []
for c in cs:
    cip = bytes(int(c[i:i+2], 16) for i in range(0, len(c), 2))
    otp_pre = bytes(a ^ b for a, b in zip(cip[:8], prefix))
    y_i = int.from_bytes(otp_pre, 'big')
    y.append(y_i)
    msb_i = cip[40] ^ ord('}')
    msbs.append(msb_i)

cip1 = bytes(int(cs[0][i:i+2], 16) for i in range(0, len(cs[0]), 2))
msb = msbs[0]

A = None
B = None
for i in range(len(y) - 2):
    y0_ = y[i]
    y1_ = y[i + 1]
    y2_ = y[i + 2]
    d1 = (y1_ - y0_) % m
    d2 = (y2_ - y1_) % m
    g = gcd(d1, m)
    if d2 % g != 0:
        continue
    d1_g = d1 // g
    d2_g = d2 // g
    m_g = m // g
    inv = pow(d1_g, -1, m_g)
    A0 = (d2_g * inv) % m_g
    for t in range(g):
        candidate_A = A0 + t * m_g
        candidate_B = (y1_ - candidate_A * y0_) % m
        good = True
        for j in range(1, len(y)):
            predicted = (candidate_A * y[j - 1] + candidate_B) % m
            if predicted != y[j]:
                good = False
                break
        if good:
            A = candidate_A
            B = candidate_B
            break
    if A is not None:
        break

if A is None:
    print("Failed to find A, B. Try more requests.")
    exit(1)

solutions = []
mod = 16
for x in range(mod):
    if pow(x, 6, mod) == A % mod:
        solutions.append(x)

for current_k in range(5, 65):
    new_mod = 1 << current_k
    new_solutions = []
    step = 1 << (current_k - 1)
    for s in solutions:
        for delta in [0, 1]:
            x = s + delta * step
            if pow(x, 6, new_mod) == A % new_mod:
                new_solutions.append(x % m)
    solutions = new_solutions

a_candidates = [a for a in solutions if a % 8 == 5]

for a in a_candidates:
    S = 0
    p = 1
    for i in range(steps):
        S = (S + p) % m
        p = (p * a) % m
    g = 1
    temp_s = S
    while temp_s % 2 == 0:
        temp_s //= 2
        g *= 2
    if B % g != 0:
        continue
    S_g = S // g
    B_g = B // g
    m_g = m // g
    inv = pow(S_g, -1, m_g)
    c0 = (B_g * inv) % m_g
    for t in range(g):
        c = (c0 + t * m_g) % m
        if c % 2 == 0:
            continue
        inv_a = pow(a, -1, m)
        seed = ((y[0] - c) * inv_a) % m
        x = seed
        otp = b''
        x_last = None
        for _ in range(steps):
            x = (a * x + c) % m
            x_last = x
            otp += x.to_bytes(8, 'big')
        otp = otp[:p_len]
        if x_last.to_bytes(8, 'big')[0] != msb:
            continue
        flag = bytes(u ^ v for u, v in zip(cip1, otp))
        if flag.startswith(b'BHFlagY{') and flag.endswith(b'}') and all(32 <= b <= 126 or b in b'_' for b in flag[8:-1]):
            print("Flag:", flag.decode())
            exit(0)

print("No valid flag found. Try more requests or check extraction.")