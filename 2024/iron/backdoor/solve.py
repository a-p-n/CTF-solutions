from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

class Curve:
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P.x == Q.x and P.y != Q.y:
            return None
        if P != Q:
            lam = (Q.y - P.y) * pow(Q.x - P.x, -1, self.p) % self.p
        else:
            lam = (3 * P.x**2 + self.a) * pow(2 * P.y, -1, self.p) % self.p
        x3 = (lam**2 - P.x - Q.x) % self.p
        y3 = (lam * (P.x - x3) - P.y) % self.p
        return Point(x3, y3)

    def scalar_multiply(self, k, P):
        Q = None
        while k:
            if k & 1:
                Q = self.add(Q, P)
            P = self.add(P, P)
            k >>= 1
        return Q

    def point_from_x(self, x):
        y_squared = (x**3 + self.a * x + self.b) % self.p
        y = pow(y_squared, (self.p + 1) // 4, self.p)
        if pow(y, 2, self.p) == y_squared:
            return Point(x, y)
        return Point(x, self.p - y)

class Dual_EC_Exploit:
    def __init__(self):
        p = 229054522729978652250851640754582529779
        a = -75
        b = -250
        self.curve = Curve(p, a, b)
        self.P = Point(97396093570994028423863943496522860154, 2113909984961319354502377744504238189)
        self.Q = Point(137281564215976890139225160114831726699, 111983247632990631097104218169731744696)
        
        # Pre-computed d such that Q = d * P
        self.d = 61015590686868528506481267201857382147  # This would be pre-computed
        assert self.curve.scalar_multiply(self.d, self.P).x == self.Q.x

    def reconstruct_state(self, sample):
        R = self.curve.point_from_x(sample)
        next_state = self.curve.scalar_multiply(self.d, R).x
        return next_state

    def predict_next(self, state):
        next_point = self.curve.scalar_multiply(state, self.Q)
        return next_point.x

def main():
    sample = 222485190245526863452994827085862802196
    encrypted = b'BI\xd5\xfd\x8e\x1e(s\xb3vUhy\x96Y\x8f\xceRr\x0c\xe6\xf0\x1a\x88x\xe2\xe9M#]\xad\x99H\x13+\x9e5\xfd\x9b \xe6\xf0\xe10w\x80q\x8d'

    exploit = Dual_EC_Exploit()
    
    state = exploit.reconstruct_state(sample)
    
    r1 = exploit.predict_next(state)
    state = exploit.curve.scalar_multiply(state, exploit.P).x
    r2 = exploit.predict_next(state)
    state = exploit.curve.scalar_multiply(state, exploit.P).x
    r3 = exploit.predict_next(state)

    key = long_to_bytes((r1 << 128) + r2)
    iv = long_to_bytes(r3)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    
    print("Decrypted flag:", decrypted.decode())

if __name__ == "__main__":
    main()