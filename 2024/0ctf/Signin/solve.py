from Crypto.Util.number import bytes_to_long
from string import ascii_lowercase
from sympy import nextprime
import numpy as np
import random
import signal
import os


def _handle_timeout(signum, frame):
    raise TimeoutError('function timeout')

timeout = 60
signal.signal(signal.SIGALRM, _handle_timeout)
signal.alarm(timeout)


def uniform_sample(n, bound, SecureRandom):
    return [SecureRandom.randrange(-bound, bound) for _ in range(n)]


def ternary_sample(n, ternaryL, SecureRandom):
    return [ternaryL[int(_)] for __ in range(n // 5) for _ in np.base_repr(ord(SecureRandom.choice(ascii_lowercase)), 3)]

n = 67
m = 110
q = nextprime(212)
e_L = [0, 101, 55]
R_s= random.SystemRandom()
s = np.array(uniform_sample(n, q//2, R_s))
R_e = random.SystemRandom()
e = np.array(ternary_sample(m, e_L, R_e))
seed = os.urandom(16)
R_A = random
R_A.seed(seed)
A = np.array([uniform_sample(n, q, R_A) for _ in range(m)])
b = (A.dot(s) + e) % q
print(f"{s = }")
print(f"{seed = }")
# print(f"{b.tolist() = }")

# from sage.all import GF


def attack(q, A, b, E, S=None):
    """
    Recovers the secret key s from the LWE samples A and b.
    More information: "The Learning with Errors Problem: Algorithms" (Section 1)
    :param q: the modulus
    :param A: the matrix A, represented as a list of lists
    :param b: the vector b, represented as a list
    :param E: the possible error values
    :param S: the possible values of the entries in s (default: None)
    :return: a list representing the secret key s
    """
    m = len(A)
    n = len(A[0])
    gf = GF(q)
    pr = gf[tuple(f"x{i}" for i in range(n))]
    gens = pr.gens()

    f = []
    for i in range(m):
        p = 1
        for e in E:
            p *= (b[i] - sum(A[i][j] * gens[j] for j in range(n)) - e)
        f.append(p)

    if S is not None:
        # Use information about the possible values for s to add more polynomials.
        for j in range(n):
            p = 1
            for s in S:
                p *= (gens[j] - s)
            f.append(p)

    s = []
    for p in pr.ideal(f).groebner_basis():
        assert p.nvariables() == 1 and p.degree() == 1
        s.append(int(-p.constant_coefficient()))

    return s


print(s == attack(q, A, b, e_L))
