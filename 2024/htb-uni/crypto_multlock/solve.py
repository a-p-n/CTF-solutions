import random
import string
import time
from base64 import b64decode

def generate_key(seed, length=16):
    random.seed(seed)
    key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    return key

def polyalphabetic_decrypt(ciphertext, key):
    ciphertext = b64decode(ciphertext).decode()
    key_length = len(key)
    plaintext = []
    for i, char in enumerate(ciphertext):
        key_char = key[i % key_length]
        decrypted_char = chr(256 + ord(char) - ord(key_char))
        plaintext.append(decrypted_char)
    return ''.join(plaintext)

def xor_cipher(text, key):
    return [chr(ord(c) ^ key) for c in text]

encrypted_flags = [bytes.fromhex('00071134013a3c1c00423f330704382d00420d331d04383d00420134044f383300062f34063a383e0006443310043839004315340314382f004240331c043815004358331b4f3830'), bytes.fromhex('5d1f486e4d49611a5d1e7e6e4067611f5d5b196e5b5961405d1f7a695b12614e5d58506e4212654b5d5b196e4067611d5d5b726e4649657c5d5872695f12654d5d5b4c6e4749611b')]
pt = []

# Part 1
key_seed = 42
key = generate_key(key_seed)
next_key_seed = random.randint(1, 1000)
# key_length = len(key)
# for i in range(1,1000):
#     pt_char = []
#     for i, char in enumerate(encrypted_flags[0]):
#         key_char = key[i % key_length]
#         encrypted_char = chr((ord(char) - ord(key_char)) % 256)
#         pt_char.append(encrypted_char)
#     try: 
#         "".j


# Part 2
xor_key = 42
encrypted_half = "".join(xor_cipher(encrypted_flags[1].decode(), xor_key))
print(encrypted_half)
key = generate_key(next_key_seed)
print(polyalphabetic_decrypt(encrypted_half, key))
print(pt)
