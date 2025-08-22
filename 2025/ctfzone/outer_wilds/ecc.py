p = 0x5F1586368F278CAAFF7289F5D6E24FD229F6E1CCB86C52B5779AC853552BE79
a = 0x1337
b = 0x2A5B8AC6AA0565DEF105AE1788FC56EB75C9891062883F34A2C8DAD628C4F87
q = 0x5F1586368F278CAAFF7289F5D6E24FD20D6D6C59C6B6ACFE4272E85E7E98319
G = (
    0x4C146983EE247BCC1174004BF95282BC97BDDE453C82405B18D53E84564B250,
    0x279F15F24D01328F1488E089FC987BA0643715D6BBBC89646FBD6A3DC95B4AA,
    0x1,
)


def ecc_add(P: tuple[int], Q: tuple[int]) -> tuple[int]:
    X0, Y0, Z0 = P
    X1, Y1, Z1 = Q

    U0 = X0 * Z1**2 % p
    S0 = Y0 * Z1**3 % p
    U1 = X1 * Z0**2 % p
    S1 = Y1 * Z0**3 % p

    W = U0 - U1
    R = S0 - S1
    T = U0 + U1
    M = S0 + S1

    Z2 = W * Z0 * Z1 % p
    X2 = (R**2 - T * W**2) % p

    V = (T * W**2 - 2 * X2) % p
    Y2 = ((p + 1) >> 1) * (V * R - M * W**3) % p
    return (X2, Y2, Z2)


def ecc_dbl(P: tuple[int]) -> tuple[int]:
    X1, Y1, Z1 = P

    Z2 = 2 * Y1 * Z1 % p

    M = (3 * X1**2 + a * Z1**4) % p
    S = 4 * X1 * Y1**2 % p
    X2 = (M**2 - 2 * S) % p

    T = 8 * Y1**4 % p
    Y2 = (M * (S - X2) - T) % p

    return (X2, Y2, Z2)


def ecc_mul(P: tuple[int], n: int) -> tuple[int]:
    if n == 0:
        return None

    if n < 0:
        P = (P[0], -P[1] % p, P[2])
        n = -n
    else:
        P = (P[0], P[1], P[2])

    R = P
    trace = [(R, None)]
    for i in bin(n)[3:]:
        R = ecc_dbl(R)
        trace.append((R, False))
        if i == "1":
            R = ecc_add(R, P)
            trace.append((R, True))
    return R
