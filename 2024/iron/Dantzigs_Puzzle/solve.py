def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(a, m):
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def decrypt_knapsack(ciphertext, private_key, m, n):
    n_inv = mod_inverse(n, m)
    plaintext = ""
    for c in ciphertext:
        s = (c * n_inv) % m
        binary = ""
        for k in reversed(private_key):
            if s >= k:
                binary = "1" + binary
                s -= k
            else:
                binary = "0" + binary
        plaintext += chr(int(binary, 2))
    return plaintext

private_key = [1, 2, 4, 8, 16, 32, 64, 128]
m = 257
ciphertext = [538, 619, 944, 831, 360, 531, 468, 971, 635, 593, 655, 425, 1068, 530, 1068, 360, 706, 1068, 299, 619, 670, 1068, 891, 425, 670, 1068, 371, 670, 732, 531, 1068, 484, 372, 635, 371, 372, 237, 237, 1007]

for n in range(2, 257):
    try:
        decrypted = decrypt_knapsack(ciphertext, private_key, m, n)
        if all(32 <= ord(c) <= 126 for c in decrypted):
            print(f"Possible n: {n}")
            print(f"Decrypted message: {decrypted}")
            break
    except:
        continue
