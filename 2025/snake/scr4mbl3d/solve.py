from hashlib import sha256

P = 112100829556962061444927618073086278041158621998950683631735636667566868795947
EXPONENT = 3
ct = int("cb6de33aab01bd9f77af675905951773609fb2abac0697221a2134238540f4f3bd6f9ccf26a7a50f5a46b3399d5e714474b349f2340c40ac0b345fc360c2004b", 16)

def split(x):
    chunk1 = x // P
    chunk2 = x % P
    return chunk1, chunk2

def merge(chunk1, chunk2):
    return chunk1 * P + chunk2

def ff(x):
    return ((x * EXPONENT) * 0x5DEECE66D) % P

def gg(x):
    digest = sha256(int(x).to_bytes(256)).digest()
    return int.from_bytes(digest) % P

def inv_transform(v, u, i, constants):
    if i % 11 == 0:
        x_ = ff(u)
    else:
        x_ = gg(u)
    return u, (v - x_ - constants[i]) % P

def decrypt(ciphertext):
    for r in range(26, 54):
        ROUNDS = r
        CONSTANTS = [(44 * i ^ 3 + 98 * i ^ 2 + 172 * i + 491) % P for i in range(ROUNDS)]

        chunk1, chunk2 = split(ciphertext)

        for i in range(ROUNDS - 1, -1, -1):
            if i % 5 == 0:
                chunk1, chunk2 = inv_transform(chunk1, chunk2, i, CONSTANTS)
            else:
                chunk2, chunk1 = inv_transform(chunk2, chunk1, i, CONSTANTS)
        
        plaintext_int = merge(chunk1, chunk2)
        
        try:
            flag_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big')
            if flag_bytes.startswith(b'sn') and flag_bytes.endswith(b'}'):
                print(f"Found correct number of rounds: {ROUNDS}")
                return flag_bytes.decode()
        except Exception:
            continue
    
    return None

if __name__ == "__main__":
    flag = decrypt(ct)
    print(f"The flag is: {flag}")