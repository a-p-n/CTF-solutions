from sage.all import *

with open("out", "r") as f:
    x = f.read().strip().split("\n")

p = int(x[0])
all_inp = eval(x[1])
all_out = eval(x[2])
bits = ""

Ms = [Matrix(GF(p), i) for i in all_inp]
outs = [Matrix(GF(p), i) for i in all_out]

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

for mat in outs:
    J,P = mat.jordan_form(transformation=True)
    if legendre_symbol(J[0][0], p) != 1:
        bits += '1'
    else:
        bits += '0'
