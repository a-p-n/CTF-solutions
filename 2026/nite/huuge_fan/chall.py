from sage.all import *
from ..secret import flag
from pprint import pprint, pformat
from hashlib import sha256
import pathlib


def flip(ele):
    V = ele.parent()
    ele = list(ele)[::-1]
    return V(ele)

def to_integer(vec, be: bool=True):
    if len(vec) == 0:
        return Integer(0)
    vec = vec[::-1] if be else vec
    digits = vec.apply_map(lambda x: int(x.lift()))
    base = vec[0].parent().cardinality()
    num = Integer(0)
    for i in range(len(vec)):
        num += Integer(digits[i]) * (base ** i)
    return num

m = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D
m_len = len(str(m))
TOTAL = 60 # total acoustic traces
num_fans = 5 # number of fans in each recording

R = Zmod(m)
V = FreeModule(Zmod(int(str(m)[:4])), num_fans)

F = GF(2**448 - 2**224 - 1)
C = EllipticCurve(F, [0, 0x262A6, 0, 1, 0])
G = C.lift_x(F(5))  # base point
d = int.from_bytes(flag)


def gen_n(parts: list[int], n_nums: int = 2) -> int:
    global V
    X = [t := V( parts )] + [t := flip(t) for i in range(n_nums-1)]
    X = list(map(to_integer, X))
    n = prod(X)
    return n

def hashmsg(msg: bytes):
    return R(int.from_bytes(sha256(msg).digest()))

def sign(msg: bytes, nonce: bytes | None = None):
    global G, R, d
    while True:
        k = nonce or R.random_element()
        r = R((k * G).x())
        if r != 0:
            break
    z = hashmsg(msg)
    s = (z + r * d) / k
    return r, s

def record():
    while True:
        try:
            nonces = sorted([R.random_element() for _ in range(num_fans)])
            secret_identity = [int(str(int(nonce)).rjust(m_len)[:4]) for nonce in nonces]
            break
        except ValueError:
            continue
    n = gen_n(parts = secret_identity)
    signs = list()
    for nonce in nonces:
        msg = os.urandom(16) # starting temperature
        r, s = sign(msg, nonce)
        signs.append((msg.hex(), r, s))
    return (n, signs)

if __name__ == "__main__":
    recordings = list()
    for i in range(TOTAL // num_fans):
        recordings.append(record())
    pprint(recordings)

    with open(pathlib.Path(__file__).parent / "out.txt", "w") as f:
        f.write(pformat(recordings))
