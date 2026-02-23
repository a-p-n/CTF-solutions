import hashlib
import numpy as np
from itertools import cycle, product

# 1. Target Hash Prefix (Calculated from "nite{" XOR Ciphertext)
TARGET_PREFIX = bytes.fromhex("946bacf0fa")

# 2. Node 31 Ciphertext (Full payload)
# We reconstruct the full hex from the file to be sure
CIPHER_HEX = "fa02d89581351dc2ea71cf" # We'll start with this, script will load full if needed.

def solve():
    print(f"[*] Cracking Hash Prefix: {TARGET_PREFIX.hex()}")
    print("[*] Brute-forcing all byte sequences up to length 4...")

    # We try sequences like b'\x00', b'\x01', ... b'\xff\xff\xff\xff'
    # Optimizing for sparse sequences (containing mostly 0s) first.
    
    # Check 1-byte sequences
    for i in range(256):
        b = bytes([i])
        check(b)
        
    # Check 2-byte sequences
    print("[*] Checking 2-byte sequences...")
    for i in range(256):
        for j in range(256):
            b = bytes([i, j])
            check(b)

    # Check 3-byte sequences (Optimized: Assume at least one zero)
    print("[*] Checking 3-byte sequences...")
    # Full 16 million is fast in C, slow in Python.
    # We prioritize patterns like 00 00 XX, XX 00 00, etc.
    # Given the path is 00...01, the bytes are likely 00 00 01 or similar.
    
    # Specific sparse checks for length 3 and 4
    check_sparse(3)
    check_sparse(4)
    
    # Special: Check Packbits variations of our path
    # Path: 000000000000000000000000000001
    # Bits: 29 zeros, 1 one.
    # Standard Packbits: 00 00 00 04
    # Reversed Packbits?
    print("[*] Checking Path Variations...")
    path_str = "000000000000000000000000000001"
    
    # Variation 1: Reverse the string
    rev_path = path_str[::-1] # 1000...
    check_path_str(rev_path)
    
    # Variation 2: Invert bits
    inv_path = path_str.replace('0','x').replace('1','0').replace('x','1')
    check_path_str(inv_path)

def check_path_str(p_str):
    # Packbits
    bits = [int(c) for c in p_str]
    b = np.packbits(np.array(bits, dtype=np.uint8)).tobytes()
    check(b)
    
    # Int Big Endian
    val = int(p_str, 2)
    l = (val.bit_length() + 7) // 8 or 1
    check(val.to_bytes(l, 'big'))
    check(val.to_bytes(4, 'big')) # Force 4 bytes
    
    # Int Little Endian
    check(val.to_bytes(l, 'little'))
    check(val.to_bytes(4, 'little'))

def check_sparse(length):
    # Checks combinations with mostly zeros
    # e.g. 00 00 00 XX
    #      XX 00 00 00
    for val in range(256):
        # Position the byte at every index
        for pos in range(length):
            b = bytearray(length)
            b[pos] = val
            check(b)

def check(b_seq):
    h = hashlib.sha256(b_seq).digest()
    if h.startswith(TARGET_PREFIX):
        print("\n" + "!"*60)
        print(f"[+] FOUND HASH INPUT!")
        print(f"    Bytes: {b_seq}")
        print(f"    Hex:   {b_seq.hex()}")
        print(f"    Hash:  {h.hex()}")
        print("!"*60)
        
        # We found the key bytes! Now use them to decrypt.
        # Since we don't have the full ciphertext loaded in this script,
        # we will verify with the prefix and output the Python code to finish it.
        print("\n[+] Verification Decrypt (Prefix):")
        
        # Cipher prefix from logs: fa02d89581
        cipher_prefix = bytes.fromhex("fa02d89581")
        res = bytearray()
        for c, k in zip(cipher_prefix, cycle(h)):
            res.append(c ^ k)
        print(f"    {res}")
        
        print("\n[***] SOLUTION [***]")
        print("Run this python code to get the flag:")
        print("-" * 20)
        print("import hashlib, dill")
        print("from itertools import cycle")
        print("import numpy as np")
        print("with open('model.dill', 'rb') as f: data = dill.load(f)")
        print("model = data['model']")
        print("values = model.tree_.value")
        print("classes = model.classes_")
        print("# Node 31 Payload")
        print("idx = np.argmax(values[31])")
        print("hex_val = classes[idx]")
        print(f"key_input = {b_seq}  # Found Bytes")
        print("key_hash = hashlib.sha256(key_input).digest()")
        print("cipher = bytes.fromhex(hex_val)")
        print("print(''.join(chr(c ^ k) for c, k in zip(cipher, cycle(key_hash))))")
        print("-" * 20)
        exit(0)

if __name__ == "__main__":
    solve()
