from functools import reduce
from math import gcd
from pwn import *
from sympy import primerange
from sympy.ntheory.modular import solve_congruence
from base64 import b64decode
from tqdm import tqdm

def get_encrypted():
    p.sendlineafter(b"> ", b"2")
    p.recvuntil(b"Here you go: ")
    return p.recvline().decode().strip('\n')

def generate(n):
    """Generate a string of n unique characters"""
    return ''.join(chr(i) for i in range(0x20, 0x20 + n))

def get_samples(n):
    p.sendlineafter(b"> ", b"1")
    msg = generate(n).encode()
    p.sendlineafter(b"What do you have to say?\n", msg)

    response = p.recvline().decode().strip('\n')
    if "Are you trying to hack me" in response:
        raise ValueError("Invalid length")

    assert len(set(response)) == n
    return [ord(c)-0x20 for c in response[-n:]]

def find_lcg_state(i):
    samples = []
    for n in tqdm(list(primerange(500, 600)), desc=f"State {i}", position=1, leave=False):
        try:
            output = get_samples(n)
            samples.append((output[i], n))
        except ValueError:
            pass

    tqdm.write(str(samples))
    return solve_congruence(*samples)[0]


# Math stuff (source: https://tailcall.net/posts/cracking-rngs-lcgs/)
class LCG:
    def __init__(self, a, c, m, seed):
        self.a = a
        self.c = c
        self.m = m

        self.a_inv = pow(self.a, -1, self.m)
        self.state = seed

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def prev(self):
        self.state = (self.a_inv * (self.state - self.c)) % self.m
        return self.state

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(b, n):
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * modinv(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)

def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)


# Final attack
def generate_permutation(l, L: LCG):
    permutation = []
    chosen_nums = set()
    while len(permutation) < l:
        pos = L.next()
        pos = pos % l
        if pos not in chosen_nums:
            permutation.append(pos)
            chosen_nums.add(pos)

    return permutation

if __name__ == "__main__":
    while True:
        try:
            # p = process('./shuffler.py')
            p = remote("chall.lac.tf", 31172)

            encrypted = get_encrypted()
            # print(encrypted)

            states = [find_lcg_state(i) for i in tqdm(range(6), desc="All states", position=0, leave=False)]
            # print(states)

            m, a, c = crack_unknown_modulus(states)
            m, a, c = int(m), int(a), int(c)
            seed = int(states[0])
            tqdm.write(f"{m=}, {a=}, {c=}, seed={seed}")
            lcg = LCG(a, c, m, seed)
            lcg.prev()  # Back to seed instead of first result

            # for i in range(4):
            #     print(lcg.next())

            permutation = generate_permutation(len(encrypted), lcg)
            tqdm.write(str(permutation))

            plaintext = ''.join(encrypted[permutation.index(i)]
                                for i in range(len(encrypted)))
            decoded = b64decode(plaintext.strip('.'))

            tqdm.write(decoded.decode())
            tqdm.write(decoded.decode())
            tqdm.write(decoded.decode())
            print(decoded.decode())
            print(decoded.decode())
            print(decoded.decode())

            p.close()
            break
        except Exception as e:
            print(e)
            p.close()
            continue
