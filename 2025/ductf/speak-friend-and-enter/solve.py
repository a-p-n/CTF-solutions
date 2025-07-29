import json
import os
from binascii import unhexlify
from pwn import remote

from Crypto.Cipher import AES
from Crypto.Hash import SHA512, CMAC
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime

HOST = "chal.2025.ductf.net"
PORT = 30008

NIST_KEY_HEX = '2b7e151628aed2a6abf7158809cf4f3c'
SERVER_CMAC_HEX = '9d4dfd27cb483aa0cf623e43ff3d3432'
KEY_BITS = 2048
KEY_BYTES = KEY_BITS // 8
BLOCK_SIZE = AES.block_size

def correct_left_shift(data: bytes) -> bytes:
    """
    Correctly performs a bitwise left shift on a 128-bit value
    represented as a 16-byte string.
    """
    # Convert bytes to a single large integer for easy shifting
    val = int.from_bytes(data, 'big')
    # Perform the 128-bit left shift
    val <<= 1
    # Convert back to a 17-byte array to handle potential overflow
    shifted_bytes = val.to_bytes(17, 'big')
    # Return the last 16 bytes
    return shifted_bytes[1:]

def generate_subkeys(key):
    """
    Generates the K1 and K2 subkeys for AES-CMAC using the corrected
    128-bit shift logic.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    const_zero = b'\x00' * BLOCK_SIZE
    const_Rb = 0x87 # Polynomial for 128-bit blocks

    l = cipher.encrypt(const_zero)
    
    # --- Calculate K1 ---
    msb_l = l[0] >> 7
    k1_shifted = correct_left_shift(l)
    if msb_l:
        # If MSB of L was 1, XOR the result with Rb
        k1_int = int.from_bytes(k1_shifted, 'big') ^ const_Rb
        k1 = k1_int.to_bytes(16, 'big')
    else:
        k1 = k1_shifted

    # --- Calculate K2 ---
    msb_k1 = k1[0] >> 7
    k2_shifted = correct_left_shift(k1)
    if msb_k1:
        # If MSB of K1 was 1, XOR the result with Rb
        k2_int = int.from_bytes(k2_shifted, 'big') ^ const_Rb
        k2 = k2_int.to_bytes(16, 'big')
    else:
        k2 = k2_shifted
        
    return k1, k2

def find_prime_with_target_cmac(key, target_mac):
    """
    Finds a 2048-bit prime number `p` such that CMAC(key, long_to_bytes(p)) == target_mac.
    This is the core of the attack.
    """
    print("[*] Starting search for a prime with the correct CMAC. This may take a moment...")
    
    k1, k2 = generate_subkeys(key)
    cipher = AES.new(key, AES.MODE_ECB)
    decryptor = AES.new(key, AES.MODE_ECB)

    num_blocks = KEY_BYTES // BLOCK_SIZE
    prefix_len = (num_blocks - 1) * BLOCK_SIZE # 240 bytes
    
    attempts = 0
    while True:
        attempts += 1
        if attempts % 100 == 0:
            print(f"[.] Attempts: {attempts}")

        prefix = b'\x80' + os.urandom(prefix_len - 1)

        intermediate_state = b'\x00' * BLOCK_SIZE
        for i in range(num_blocks - 1):
            block = prefix[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
            intermediate_state = cipher.encrypt(bytes(a ^ b for a, b in zip(intermediate_state, block)))

        decrypted_mac = decryptor.decrypt(target_mac)
        last_block_xor_k1 = bytes(a ^ b for a, b in zip(decrypted_mac, intermediate_state))
        last_block = bytes(a ^ b for a, b in zip(last_block_xor_k1, k1))

        candidate_bytes = prefix + last_block
        candidate_p = bytes_to_long(candidate_bytes)

        if isPrime(candidate_p):
            # Optional: Verify our work before sending to the server
            verifier = CMAC.new(key, ciphermod=AES)
            verifier.update(candidate_bytes)
            if verifier.digest() == target_mac:
                print(f"\n[+] Found a suitable and VERIFIED prime after {attempts} attempts!")
                print(f"  - Prime (p): {hex(candidate_p)[:64]}...")
                return candidate_p
            else:
                print("[!] Found a prime, but its MAC was incorrect. Logic error still exists. Retrying...")


def solve():
    key = unhexlify(NIST_KEY_HEX)
    target_mac = unhexlify(SERVER_CMAC_HEX)
    
    prime_modulus = find_prime_with_target_cmac(key, target_mac)

    print("\n[*] Connecting to the service...")
    io = remote(HOST, PORT)

    challenge_line = io.recvline_contains(b'challenge string').decode().strip()
    challenge_string = challenge_line.split(': ')[1].encode()
    print(f"[*] Received challenge: {challenge_string.decode()}")

    print("[*] Forging the RSA signature...")
    e = 65537
    s = bytes_to_long(SHA512.new(challenge_string).digest())
    phi = prime_modulus - 1
    d = pow(e, -1, phi)
    signature = pow(s, d, prime_modulus)
    
    payload = json.dumps({
        "public_key": prime_modulus,
        "signature": signature
    })
    
    print("[*] Sending forged signature and public key...")
    io.sendlineafter(b':', payload.encode())
    
    print("\n[+] Flag response:")
    print(io.recvall().decode())


if __name__ == "__main__":
    solve()
