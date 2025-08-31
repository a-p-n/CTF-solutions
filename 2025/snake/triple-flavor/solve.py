from pwn import *
from string import ascii_lowercase, digits
from itertools import product
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

HOST = "triple-flavor.challs.snakectf.org"
PORT = 1337

SECRET_LEN = 15
KEY_LEN = SECRET_LEN // 3
CHARSET = ascii_lowercase + digits
BLOCK_SIZE = AES.block_size

def xor(a: bytes, b: bytes):
    return bytes([x ^ y for x, y in zip(a, b)])

def get_response(p, pt_hex):
    p.sendlineafter(b'(in hex): ', pt_hex.encode())
    response = p.recvline().strip().split(b': ')[1]
    iv0 = bytes.fromhex(response[:32].decode())
    iv1 = bytes.fromhex(response[32:64].decode())
    ct3 = bytes.fromhex(response[64:].decode())
    return iv0, iv1, ct3

def get_key_from_seed(seed):
    return sha256(seed.encode()).digest()[:16]

def generate_tweak(iv, num_blocks):
    twks = [sha256(iv + i.to_bytes(1, 'big')).digest()[:16] for i in range(num_blocks)]
    return b''.join(twks)
    
def generate_ofb_stream(key, iv, num_blocks):
    cipher = AES.new(key, AES.MODE_ECB)
    stream = b''
    last_block = iv
    for _ in range(num_blocks):
        last_block = cipher.encrypt(last_block)
        stream += last_block
    return stream


def find_seed0():
    log.info("Starting differential attack to find seed0...")
    
    P0 = b'\x00' * BLOCK_SIZE
    P0_prime = b'\x01' * BLOCK_SIZE
    
    P1 = b'\x02' * BLOCK_SIZE
    
    pt_A = (P0 + P1 + P1).hex()
    pt_B = (P0_prime + P1 + P1).hex()
    
    p = remote(HOST, PORT, ssl=True)
    p.sendlineafter(b"enter your team token: ", b"52c1d0de5320193381d02a80d2825f73")
    _, _, ct3_A = get_response(p, pt_A)
    p.close()
    
    p = remote(HOST, PORT, ssl=True)
    p.sendlineafter(b"enter your team token: ", b"52c1d0de5320193381d02a80d2825f73")
    _, _, ct3_B = get_response(p, pt_B)
    p.close()
    
    ct3_A_block1 = ct3_A[BLOCK_SIZE:2*BLOCK_SIZE]
    ct3_B_block1 = ct3_B[BLOCK_SIZE:2*BLOCK_SIZE]
    target_diff = xor(ct3_A_block1, ct3_B_block1)
    
    log.success(f"Calculated target differential: {target_diff.hex()}")
    log.info("Brute-forcing seed0... (this might take a minute)")
    
    for i, seed_chars in enumerate(product(CHARSET, repeat=KEY_LEN)):
        candidate_seed = "".join(seed_chars)
        
        if i % 5000000 == 0 and i > 0:
            log.info(f"Checked {i}/{len(CHARSET)**KEY_LEN} seeds for seed0...")
            
        candidate_key0 = get_key_from_seed(candidate_seed)
        cipher = AES.new(candidate_key0, AES.MODE_ECB)
        
        # Calculate the differential with the candidate key
        test_diff = xor(cipher.encrypt(P0), cipher.encrypt(P0_prime))
        
        if test_diff == target_diff:
            log.success(f"Found seed0: {candidate_seed}")
            return candidate_seed
            
    return None

# --- Attack Stage 2: Meet-in-the-Middle for seed1 and seed2 ---
def find_seed1_and_seed2(key0):
    log.info("Starting meet-in-the-middle attack for seed1 and seed2...")
    
    # We can use any known plaintext. All zeros is easy.
    # 2 blocks are enough for the MiTM.
    pt = b'\x00' * (2 * BLOCK_SIZE)
    
    # Get a ciphertext sample
    p = remote(HOST, PORT, ssl=True)
    p.sendlineafter(b"enter your team token: ", b"52c1d0de5320193381d02a80d2825f73")
    iv0, iv1, ct3 = get_response(p, pt.hex())
    p.close()
    
    # We know key0, so we can compute ct1
    cipher0_ecb = AES.new(key0, AES.MODE_ECB)
    ct1 = cipher0_ecb.encrypt(pad(pt, BLOCK_SIZE))
    
    # The tweak T is also known
    T = generate_tweak(iv1, len(ct1) // BLOCK_SIZE)

    # From the crypto, we have: CBC-Encrypt(k2, ct3) = ct1 ^ OFB-Stream(k1) ^ T
    # LHS = CBC-Encrypt(k2, ct3)
    # RHS = ct1 ^ OFB-Stream(k1) ^ T

    log.info("Building table for LHS (brute-forcing seed2)...")
    lookup_table = {}
    for i, seed2_chars in enumerate(product(CHARSET, repeat=KEY_LEN)):
        candidate_seed2 = "".join(seed2_chars)
        
        if i % 5000000 == 0 and i > 0:
            log.info(f"Checked {i}/{len(CHARSET)**KEY_LEN} seeds for seed2...")
            
        candidate_key2 = get_key_from_seed(candidate_seed2)
        cipher2_cbc = AES.new(candidate_key2, AES.MODE_CBC, iv1)
        lhs = cipher2_cbc.encrypt(ct3)
        lookup_table[lhs] = candidate_seed2

    log.success("Finished building LHS table.")
    log.info("Searching for a match by brute-forcing seed1...")
    
    for i, seed1_chars in enumerate(product(CHARSET, repeat=KEY_LEN)):
        candidate_seed1 = "".join(seed1_chars)
        
        if i % 5000000 == 0 and i > 0:
            log.info(f"Checked {i}/{len(CHARSET)**KEY_LEN} seeds for seed1...")
            
        candidate_key1 = get_key_from_seed(candidate_seed1)
        
        # Calculate RHS
        ofb_stream = generate_ofb_stream(candidate_key1, iv0, len(ct1) // BLOCK_SIZE)
        rhs = xor(xor(ct1, ofb_stream), T)
        
        if rhs in lookup_table:
            found_seed2 = lookup_table[rhs]
            log.success(f"Found seed1: {candidate_seed1}")
            log.success(f"Found seed2: {found_seed2}")
            return candidate_seed1, found_seed2
            
    return None, None

if __name__ == "__main__":
    seed0 = find_seed0()
    if not seed0:
        log.failure("Could not find seed0.")
        exit(1)
        
    key0 = get_key_from_seed(seed0)
    
    seed1, seed2 = find_seed1_and_seed2(key0)
    if not seed1 or not seed2:
        log.failure("Could not find seed1 or seed2.")
        exit(1)

    secret_token = seed0 + seed1 + seed2
    log.success(f"Recovered secret token: {secret_token}")

    p = remote(HOST, PORT, ssl=True)
    p.sendlineafter(b"enter your team token: ", b"52c1d0de5320193381d02a80d2825f73")
    p.sendlineafter(b'(in hex): ', b'00')
    p.recvline()
    p.sendlineafter(b'guess: ', secret_token.encode())
    
    flag = p.recvline().decode().strip()
    log.success(f"Flag: {flag}")
    p.close()