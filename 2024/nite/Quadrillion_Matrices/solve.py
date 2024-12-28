with open("out", "r") as f:
    x = f.read().strip().split("\n")

p = int(x[0])
inp = eval(x[1])
out = eval(x[2])
bits = ""

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

def square_root(a, p):
    # Tonelli–Shanks algorithm
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def d2solve(a, b, c):
    a %= p
    b %= p
    c %= p
    delta = (b**2 - 4 * a * c) % p
    sq = square_root(delta, p)
    if delta != 0: assert sq != 0
    sq1 = +sq
    sq2 = (p-sq) % p
    bot = pow(2 * a, -1, p)
    return ((-b + sq1) * bot) % p, ((-b + sq2) * bot) % p


"""
Find eigenvalues of a matrix m
"""
def eigenvals(m):
    a, b, c, d = m[0][0], m[0][1], m[1][0], m[1][1]
    A = 1
    B = -(a + d)
    C = a * d - b * c
    return d2solve(A, B, C)


for i in range(len(out)):
    m = out[i]
    # print(eigenvals(m))
    # a, b, c, d = m[0][0], m[0][1], m[1][0], m[1][1]
    # A = (1)%p
    # B = (-(a + d))%p
    # C = (a * d - b * c)%p
    # delta = (B**2 - 4 * A * C) % p
    if legendre_symbol(eigenvals(m)[0], p) != 1:
        bits += '1'
    else:
        bits += '0'
    print(eigenvals(m)[0])
print(bits)