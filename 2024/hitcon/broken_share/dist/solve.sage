import itertools
from hashlib import sha256
from Crypto.Cipher import AES

p = 65537
F = GF(p)
PR.<x> = PolynomialRing(F)

def find_polynomial(shares, t):
    for coeffs in itertools.product(range(p), repeat=t):
        poly = PR(list(coeffs))
        if all(poly(x) == y for x, y in shares):
            return poly
    return None

shares = [(18565, 15475), (4050, 20443), (7053, 28908), (46320, 10236), (12604, 25691), (34890, 55908), (20396, 47463), (16840, 10456), (29951, 4074), (43326, 55872), (15136, 21784), (42111, 55432), (32311, 30534), (28577, 18600), (35425, 34192), (38838, 6433), (40776, 31807), (29826, 36077), (39458, 24811), (32328, 28111), (38079, 11245), (36995, 27991), (26261, 59236), (42176, 20756), (11071, 50313), (31327, 7724), (14212, 45911), (22884, 22299), (18878, 50951), (23510, 24001), (61462, 57669), (46222, 34450), (29, 5836), (50316, 15548), (24558, 15321), (9571, 19074), (11188, 44856), (36698, 40296), (6125, 33078), (42862, 49258), (22439, 56745), (37914, 56174), (53950, 16717), (17342, 59992), (48528, 39826), (59647, 57687), (30823, 36629), (65052, 7106)]
ct = b'\xa4\x17#U\x9d[2Sg\xb9\x99B\xe8p\x8b\x0b\x14\xf0\x04\xde\x88\xb9\xf6\xceM/\xea\xbf\x15\x99\xd7\xaf\x8c\xa1t\xa4%~c%\xd2\x1dNl\xbaF\x92\xae(\xca\xf8$+\xebd;^\xb8\xb3`\xf0\xed\x8a\x9do'

poly = find_polynomial(shares, 24)
if poly:
    ks = [poly(i) for i in range(24)]
    key = sha256(repr(ks).encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR, nonce=ct[:8])
    print(cipher.decrypt(ct[8:]))
else:
    print("Polynomial not found")