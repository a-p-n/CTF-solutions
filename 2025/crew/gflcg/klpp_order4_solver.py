#!/usr/bin/env python3
import ast
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def bits_le(x, n=64):
    return [(x>>i)&1 for i in range(n)]

def solve_order_k(vals, k):
    N = len(vals)
    T = N - k
    m = 64*k + 1
    sols = []
    for bit in range(64):
        rows = []
        for i in range(T):
            row = 0
            for lag in range(k):
                vec = bits_le(vals[k+i-1-lag])
                for j,b in enumerate(vec):
                    if b: row |= 1 << (lag*64 + j)
            row |= 1 << (64*k)  # bias
            bbit = (vals[k+i] >> bit) & 1
            row |= bbit << m
            rows.append(row)
        rowi = 0
        where = [-1]*m
        for col in range(m):
            piv = None
            for r in range(rowi, len(rows)):
                if (rows[r]>>col)&1: piv=r; break
            if piv is None: continue
            rows[rowi], rows[piv] = rows[piv], rows[rowi]
            where[col] = rowi
            for r in range(rowi+1, len(rows)):
                if (rows[r]>>col)&1: rows[r] ^= rows[rowi]
            rowi += 1
            if rowi == len(rows): break
        for r in range(rowi, len(rows)):
            if (rows[r] & ((1<<m)-1)) == 0 and ((rows[r]>>m)&1):
                return None
        x = [0]*m
        for col in range(m-1, -1, -1):
            rix = where[col]
            if rix == -1: x[col]=0
            else:
                rhs = (rows[rix]>>m)&1
                for j in range(col+1, m):
                    if (rows[rix]>>j)&1: rhs ^= x[j]
                x[col] = rhs
        sols.append(x)
    return sols

def predict_next(vals, sols, k):
    def step(prev_states):
        out = 0
        for bit in range(64):
            row = sols[bit]
            acc = 0
            for lag in range(k):
                vec = bits_le(prev_states[lag])
                for j in range(64):
                    acc ^= row[lag*64 + j] & vec[j]
            acc ^= row[64*k] & 1
            out |= (acc&1) << bit
        return out & ((1<<64)-1)
    history = [vals[-1 - i] for i in range(k)]
    v1 = step(history)
    history = [v1] + history[:-1]
    v2 = step(history)
    return v1, v2

def main(path='out.txt'):
    txt = Path(path).read_text()
    d={}
    for line in txt.splitlines():
        if '=' in line:
            k,v=line.split('=',1)
            d[k.strip()] = ast.literal_eval(v.strip())
    vals = [int(x) & ((1<<64)-1) for x in d['values']]
    msg = bytes(d['msg'])
    # find smallest k<=5 that fits
    sols=None; k=None
    for kk in range(1,6):
        s = solve_order_k(vals, kk)
        if s is not None:
            sols=s; k=kk; break
    if sols is None:
        raise SystemExit("No small-k model fits")
    v1,v2 = predict_next(vals, sols, k)
    I = (v1 + (v2<<64)) % (1<<128)
    key = I.to_bytes(16,'big')
    pt = AES.new(key,AES.MODE_ECB).decrypt(msg)
    try: pt = unpad(pt,16)
    except: pass
    print("k=",k)
    print("v1=", v1)
    print("v2=", v2)
    print("key=", key.hex())
    print("PT=", pt.decode('utf-8', errors='ignore'))

if __name__ == "__main__":
    from Crypto.Cipher import AES
    main("/mnt/data/out.txt")
