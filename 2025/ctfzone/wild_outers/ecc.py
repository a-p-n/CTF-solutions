p = 0x2B4FEE00BBEA53E7EA6D61E02E7307264849E2A44023465A5CFFD3FEF70BEC487D57BEDCE3D24D
A = 0x2135718C8684ED9EFC6852339B8F101535AA890B58AECEF1CF8DA7EEACA95126300CBFF3B591DE
G = (
    0x61E4BA1344D02A3BAE362C4B76D152B95CB645D200C06BBFC3E45235E95F6E1ED2285EE820092,
    1,
)
o = 0x2382D1316184B6E50D3B0CB74B27A0C0E0EFA52B029DFF0A78F6918A35E9611F5C4D916C3


# https://eprint.iacr.org/2025/672.pdf
def cDBL(P: tuple[int], A24: int) -> tuple[int]:
    XP, ZP = P

    t0 = (XP + ZP) ** 2 % p
    t1 = (XP - ZP) ** 2 % p
    X2 = t0 * t1 % p

    t2 = (t0 - t1) % p
    t0 = A24 * t2 % p
    Z2 = t2 * (t0 + t1) % p

    return (X2, Z2)


def cADD(P: tuple[int], Q: tuple[int], ixPQ: int, izPQ: int) -> tuple[int]:
    XP, ZP = P
    XQ, ZQ = Q

    t0 = (XP - ZP) * (XQ + ZQ) % p
    t1 = (XP + ZP) * (XQ - ZQ) % p

    XR = -((p - 1) >> 2) * ixPQ * (t0 + t1) ** 2 % p
    ZR = -((p - 1) >> 2) * izPQ * (t0 - t1) ** 2 % p
    return (XR, ZR)


def swap_i(x: int, y: int, f: bool, n: int = p.bit_length()) -> tuple[int]:
    mask = 2**n - f
    tmp = (x ^ y) & mask
    return x ^ tmp, y ^ tmp


def swap_p(P: tuple[int], Q: tuple[int], f: int) -> tuple[tuple[int]]:
    PX, QX = swap_i(P[0], Q[0], f)
    PZ, QZ = swap_i(P[1], Q[1], f)
    return (PX, PZ), (QX, QZ)


def cLadder(P: tuple[int], Q: tuple[int], P_Q: tuple[int], n: int):
    A24 = (A + 2) >> 2

    S0, S1, T = ((1, 0), P, Q)

    iP = (pow(P[0], -1, p), pow(P[1], -1, p))
    iQ = (pow(Q[0], -1, p), pow(Q[1], -1, p))
    iP_Q = (pow(P_Q[0], -1, p), pow(P_Q[1], -1, p))

    b = n.bit_length()
    bits = [int(x) for x in bin(n)[2:]]

    prev = 0
    for i in range(b):
        fi = bits[i]
        cs = fi ^ prev

        R = cADD(S0, S1, iP[0], iP[1])

        S0, S1 = swap_p(S0, S1, cs)
        iQ, iP_Q = swap_p(iQ, iP_Q, cs)

        T = cADD(T, S0, iQ[0], iQ[1])
        S0 = cDBL(S0, A24)
        S1 = R

        prev = fi

    S0, _ = swap_p(S0, S1, prev)
    return S0, T


def cLadderS(P: tuple[int], n: int):
    A24 = (A + 2) >> 2

    S0, S1 = ((1, 0), P)

    iP = (pow(P[0], -1, p), pow(P[1], -1, p))

    b = n.bit_length()
    bits = [int(x) for x in bin(n)[2:]]

    prev = 0
    for i in range(b):
        fi = bits[i]
        cs = fi ^ prev

        R = cADD(S0, S1, iP[0], iP[1])

        S0, S1 = swap_p(S0, S1, cs)
        S0 = cDBL(S0, A24)
        S1 = R

        prev = fi

    S0, S1 = swap_p(S0, S1, prev)
    return S0, S1
