with open("cipher.txt") as file:
    data = file.read()

RSA_A = 7   
RSA_B = 13  

def modinv(a: int, m: int = 256) -> int:
    t, newt = 0, 1
    r, newr = m, a
    while newr != 0:
        q = r // newr
        t, newt = newt, t - q * newt
        r, newr = newr, r - q * newr
    if r > 1:
        raise ValueError("a is not invertible")
    if t < 0:
        t += m
    return t

def affine_decrypt(data: bytes, a: int = RSA_A, b: int = RSA_B) -> bytes:
    a_inv = modinv(a)
    return bytes([(a_inv * (c - b)) % 256 for c in data])

def base91_decode(data):
    B91_ALPHABET = [chr(i) for i in range(33, 124)]    
    out = []
    for i in range(0, len(data), 2):
        hi_char = data[i]
        lo_char = data[i + 1]
        hi = B91_ALPHABET.index(hi_char)
        lo = B91_ALPHABET.index(lo_char)
        byte = hi * len(B91_ALPHABET) + lo
        out.append(byte)
    return bytes(out)

def get_aes_key(p) -> bytes:
    """Derive AES_KEY from flag.txt modification timestamp"""
    ts = int(p)
    return str(ts).encode()  

def xor_layer(data: bytes, key: bytes) -> bytes:
    return bytes([c ^ key[i % len(key)] for i, c in enumerate(data)])

data = base91_decode(data)
data = affine_decrypt(data, RSA_A, RSA_B)

p = 1755442345
while True:
    key = get_aes_key(p)
    flag = xor_layer(data, key)
    if b"CONGRATULATION" in flag and b"ctf" in flag and b"here is the flag" in flag:
        print(flag.decode())
        break
    p-=1