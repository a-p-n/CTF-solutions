from itertools import product
import json

def lfsr1_next(s): return s[1:] + [s[0] ^ s[2]]
def lfsr2_next(s): return s[1:] + [s[0] ^ s[1]]
def lfsr3_next(s): return s[1:] + [s[0] ^ s[4]]
def lfsr4_next(s): return s[1:] + [s[0] ^ s[2]]
def lfsr5_next(s): return s[1:] + [s[0] ^ s[1] ^ s[3] ^ s[4]]
def lfsr6_next(s): return s[1:] + [s[0] ^ s[1] ^ s[2] ^ s[5]]

def F(x1,x2,x3,x4,x5,x6):
    return (1 ^ x4 ^ (x4 & x6) ^ (x4 & x5) ^ (x4 & x5 & x6) ^ x3 ^ (x3 & x6) ^ (x3 & x5 & x6) ^ (x3 & x4) ^ (x3 & x4 & x6) ^ (x3 & x4 & x5 & x6)
            ^ (x2 & x6) ^ (x2 & x5) ^ (x2 & x5 & x6) ^ (x2 & x4) ^ (x2 & x4 & x6) ^ (x2 & x4 & x5 & x6)
            ^ (x2 & x3 & x6) ^ (x2 & x3 & x4) ^ (x2 & x3 & x4 & x5) ^ (x2 & x3 & x4 & x5 & x6)
            ^ (x1 & x6) ^ (x1 & x5) ^ (x1 & x5 & x6) ^ (x1 & x4) ^ (x1 & x3) ^ (x1 & x3 & x6) ^ (x1 & x3 & x5)
            ^ (x1 & x3 & x4) ^ (x1 & x3 & x4 & x5) ^ (x1 & x2) ^ (x1 & x2 & x5) ^ (x1 & x2 & x5 & x6)
            ^ (x1 & x2 & x4 & x6) ^ (x1 & x2 & x4 & x5 & x6) ^ (x1 & x2 & x3 & x6) ^ (x1 & x2 & x3 & x5) ^ (x1 & x2 & x3 & x5 & x6))

def gen_stream(state, nxt, L):
    s = state[:]
    out = []
    for _ in range(L):
        out.append(s[0])
        s = nxt(s)
    return out

def gf2_solve(A, b):
    A = [row[:] for row in A]
    b = b[:]
    m, n = len(A), len(A[0])
    row = 0
    pivot_cols = []
    for col in range(n):
        piv = None
        for r in range(row, m):
            if A[r][col]:
                piv = r; break
        if piv is None: continue
        A[row], A[piv] = A[piv], A[row]
        b[row], b[piv] = b[piv], b[row]
        pivot_cols.append(col)
        for r in range(m):
            if r != row and A[r][col]:
                A[r] = [A[r][c] ^ A[row][c] for c in range(n)]
                b[r] ^= b[row]
        row += 1
        if row == n: break
    x = [0]*n
    for r, col in enumerate(pivot_cols):
        s = 0
        for c in range(n):
            if c != col and A[r][c]:
                s ^= (A[r][c] & x[c])
        x[col] = s ^ b[r]
    return x

def recover(gamma):
    L = len(gamma)
    configs = {
        1: (5, lfsr1_next, 1),
        2: (7, lfsr2_next, 1),
        3: (9, lfsr3_next, 1),
        4: (11, lfsr4_next, 0),
        5: (13, lfsr5_next, 0),
        6: (19, lfsr6_next, 1),
    }

    streams = {}
    states = {}
    for i in range(1,6):
        n, nxt, flip = configs[i]
        target = [g ^ flip for g in gamma]
        best_state, best = None, -1
        for cand in product([0,1], repeat=n):
            seq = gen_stream(list(cand), nxt, L)
            score = sum(a==b for a,b in zip(seq, target))
            if score > best:
                best = score
                best_state = list(cand)
        states[i] = best_state
        streams[i] = gen_stream(best_state, nxt, L)

    f0, delta = [], []
    for t in range(L):
        x1,x2,x3,x4,x5 = streams[1][t], streams[2][t], streams[3][t], streams[4][t], streams[5][t]
        a = F(x1,x2,x3,x4,x5,0)
        b = F(x1,x2,x3,x4,x5,1)
        f0.append(a)
        delta.append(a ^ b)

    n6, nxt6, _ = configs[6]
    basis_rows = []
    for j in range(n6):
        s = [0]*n6; s[j]=1
        basis_rows.append(gen_stream(s, nxt6, L))

    A, b = [], []
    for t in range(L):
        if delta[t] == 1:
            A.append([basis_rows[j][t] for j in range(n6)])
            b.append(gamma[t] ^ f0[t])

    x6_init = gf2_solve(A, b)
    states[6] = x6_init

    def full_gamma(states):
        s1,s2,s3,s4,s5,s6 = states[1][:], states[2][:], states[3][:], states[4][:], states[5][:], states[6][:]
        out = []
        for _ in range(L):
            out.append(F(s1[0],s2[0],s3[0],s4[0],s5[0],s6[0]))
            s1 = lfsr1_next(s1); s2 = lfsr2_next(s2); s3 = lfsr3_next(s3)
            s4 = lfsr4_next(s4); s5 = lfsr5_next(s5); s6 = lfsr6_next(s6)
        return out

    assert full_gamma(states) == gamma, "reconstruction failed"

    bits = ''.join(''.join(map(str, states[i])) for i in range(1,7))
    assert len(bits) == 64
    return bits, states

def get_gamma(path="./battle_cry/gamma.json"):
    with open(path, "r") as f:
        return json.load(f)

gamma = get_gamma()
bits, _ = recover(gamma)
print(f"CTFZONE{{{bits}}}")