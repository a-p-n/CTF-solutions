import random

def xor(a, b):
    return bytes([x^y for x, y in zip(a, b)])

class CustomRandom:
    def __init__(self, m, a=None, b=None, x=None) -> None:
        if a is None:
            self.a = random.getrandbits(64)
            self.b = random.getrandbits(64)
            self.x = x
        else:
            self.a = a
            self.b = b
            self.x = x

        self.m = m

    def next_bytes(self):
        self.x = (self.a*self.x + self.b) % self.m
        return int(bin(self.x)[-16:-9],2), int(bin(self.x)[-23:-16],2)

with open('flag.enc', 'rb') as f:
    ct = f.read()

r = CustomRandom(2**64, x=9014855307380235246)

ks = [x for _ in range(len(ct)//2 + 1) for x in r.next_bytes()]

pt = xor(ct, ks[:len(ct)])

with open('decrypted_flag.png', 'wb') as f:
    f.write(pt)

print("Decryption complete. Check 'decrypted_flag.png'")
