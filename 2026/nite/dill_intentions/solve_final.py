import hashlib
import sys

# The Target Hash Prefix we calculated (from "nite{" XOR Ciphertext of Node 31)
# Node 31 Cipher: fa02d89581...
# "nite{":        6e6974657b...
# XOR:            946bacf0fa...
TARGET_PREFIX = bytes.fromhex("946bacf0fa")

def crack():
    print(f"[*] Cracking integer source for hash prefix: {TARGET_PREFIX.hex()}...")
    print("[*] Checking integers 0 to 5,000,000...")
    
    for i in range(5000000):
        if i % 1000000 == 0:
            print(f"    Progress: {i}")

        # Logic 1: Minimal Big-Endian Bytes (Matches the 'to_bytes' and 'big' constants)
        # Example: 31 -> b'\x1f', 256 -> b'\x01\x00'
        length = (i.bit_length() + 7) // 8 or 1
        try:
            b_val = i.to_bytes(length, 'big')
            h = hashlib.sha256(b_val).digest()
            
            if h.startswith(TARGET_PREFIX):
                print("\n" + "!"*60)
                print(f"[+] KEY FOUND!")
                print(f"    Integer Source: {i}")
                print(f"    Bytes Used: {b_val}")
                print("!"*60)
                decrypt_flag(i)
                return
        except:
            pass
            
        # Logic 2: Maybe Little-Endian? (Just in case)
        try:
            b_val_little = i.to_bytes(length, 'little')
            h_little = hashlib.sha256(b_val_little).digest()
            if h_little.startswith(TARGET_PREFIX):
                print(f"[+] KEY FOUND (Little Endian)! Integer: {i}")
                decrypt_flag(i, 'little')
                return
        except:
            pass

    print("[-] Failed to find integer key in range.")

def decrypt_flag(magic_int, endian='big'):
    from itertools import cycle
    import numpy as np # Used for consistency if needed, but simple xor here
    
    # Node 31 Ciphertext (hardcoded from your logs)
    # fa02d89581351dc2ea71cf...
    # We need the full hex string. Based on previous logs, it started with fa02d89581.
    # The user provided limited output, but we can reconstruct the start.
    # To get the FULL flag, we will apply this key to the hex string we extract dynamically.
    
    # Re-generating the full key hash
    length = (magic_int.bit_length() + 7) // 8 or 1
    key_bytes = magic_int.to_bytes(length, endian)
    key_hash = hashlib.sha256(key_bytes).digest()
    
    print(f"[*] Magic Key Hash: {key_hash.hex()}")
    print("[*] Use this integer in a final script to decrypt Node 31.")
    
    # We will try to decrypt the known prefix to verify
    # Cipher: fa02d89581 (first 5 bytes)
    cipher_prefix = bytes.fromhex("fa02d89581")
    res = bytearray()
    for b, k in zip(cipher_prefix, cycle(key_hash)):
        res.append(b ^ k)
    print(f"[*] Verification (first 5 chars): {res}")

if __name__ == "__main__":
    crack()
