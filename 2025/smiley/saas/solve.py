from pwn import *
import math
from functools import reduce
import random

# context.log_level = 'debug'
def gcd_list(lst):
    return reduce(math.gcd, lst)

def main():
    r = remote('smiley.cat', 46177)

    xs = [i*i for i in range(1, 100)]
    responses = []
    for x in xs:
        r.recvuntil(b'>>> ')
        r.sendline(str(x).encode())
        resp = r.recvline().strip()
        responses.append(int(resp))
    
    diffs = [r_i*r_i - x_i for r_i, x_i in zip(responses, xs)]
    n_candidate = gcd_list(diffs)
    print(f"Recovered n_candidate: {n_candidate}, bit length: {n_candidate.bit_length()}")

    factored = False
    p = None
    q = None
    attempts = 0
    while not factored and attempts < 50:
        x = random.randint(2, n_candidate-1)
        r.recvuntil(b'>>> ')
        r.sendline(str(x).encode())
        resp = r.recvline().strip()
        try:
            fx = int(resp)
        except:
            continue
        
        g = math.gcd(x, n_candidate)
        if g != 1:
            p = g
            q = n_candidate // g
            factored = True
        else:
            try:
                x_inv = pow(x, -1, n_candidate)
            except:
                continue
            kx = (fx * fx * x_inv) % n_candidate
            if kx == 1 or kx == n_candidate - 1:
                attempts += 1
                continue
            if pow(kx, 2, n_candidate) == 1:
                p = math.gcd(kx - 1, n_candidate)
                if p != 1 and p != n_candidate:
                    q = n_candidate // p
                    factored = True
        attempts += 1

    if not factored:
        print("Failed to factor n_candidate")
        exit(1)

    print(f"Factored n: p = {p}, q = {q}")
    phi = (p-1) * (q-1)
    e = 0x10001
    d = pow(e, -1, phi)

    r.recvuntil(b'>>> ')
    r.sendline(b'quit')

    m_line = r.recvline().decode().strip()
    if m_line.startswith('m = '):
        m_str = m_line.split('=')[1].strip()
        m = int(m_str)
    else:
        print("Unexpected response after quit:", m_line)
        exit(1)

    s = pow(m, d, n_candidate)
    print(f"Computed signature: {s}")

    r.recvuntil(b'>>> ')
    r.sendline(str(s).encode())
    response = r.recvline().decode().strip()
    print(response)

    r.close()

if __name__ == '__main__':
    main()