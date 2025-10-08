#!/usr/bin/env sage

# To run: sage solve.sage

from sage.all import *
from pwn import *
import json
import hashlib
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
from fastecdsa.curve import P256
from fastecdsa.point import Point

# --- Configuration ---
HOST = "flipper.p2.securinets.tn"
PORT = 6000

# --- Curve Parameters (P-256) ---
q = P256.q
G = Point(P256.gx, P256.gy, curve=P256)

# --- GCM Finite Field Setup ---
R, x = PolynomialRing(GF(2), 'x').objgen()
# GCM polynomial: x^128 + x^7 + x^2 + x + 1
modulus_poly = x**128 + x**7 + x**2 + x + 1
F = GF(2**128, name='y', modulus=modulus_poly)

# --- Helper Functions ---

def solve_ghash_equation(c1, t1, c2, t2):
    """Solves the quadratic equation for the GCM authentication key H."""
    # Ensure ciphertexts are 32 bytes (2 blocks of 16 bytes)
    if len(c1) != 32 or len(c2) != 32:
        log.error("Ciphertexts must be 32 bytes long for this solver.")
        return []

    ct1_b0 = F.fetch_int(bytes_to_long(c1[:16]))
    ct1_b1 = F.fetch_int(bytes_to_long(c1[16:]))
    ct2_b0 = F.fetch_int(bytes_to_long(c2[:16]))
    ct2_b1 = F.fetch_int(bytes_to_long(c2[16:]))
    tag_xor = F.fetch_int(bytes_to_long(t1) ^ bytes_to_long(t2))

    # The equation is: (c1_b0^c2_b0)*H^2 + (c1_b1^c2_b1)*H + tag_xor = 0
    d1 = ct1_b0 - ct2_b0  # In GF(2), subtraction is XOR
    d2 = ct1_b1 - ct2_b1
    
    H_poly = R([tag_xor, d2, d1])
    roots = H_poly.roots(ring=F)
    
    if not roots:
        log.error("No solution for H found!")
        return []
    
    return [Integer(r[0]) for r in roots]

def ghash(H_val, ct):
    """Computes the GHASH for a given ciphertext and H."""
    H = F.fetch_int(H_val)
    res = F.zero()
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    for block in blocks:
        res += F.fetch_int(bytes_to_long(block))
        res *= H
    return res

def recover_sk_hnp(r, s, z, order):
    """Recovers a small secret key using lattice reduction (solves HNP)."""
    s_inv = inverse(s, order)
    C1 = (r * s_inv) % order
    C2 = (z * s_inv) % order
    
    # We are looking for a small sk_prime in k_prime = C1*sk_prime + C2 (mod order)
    # This is a classic Hidden Number Problem setup.
    # We create a lattice and look for a short vector.
    L = Matrix(ZZ, [
        [order, 0],
        [C1, 1]
    ])
    
    # Target vector
    v = vector(ZZ, [C2, 0])
    
    # Using Babai's nearest plane algorithm to find the closest lattice vector
    sol = L.solve_left(v)
    sol = vector([round(c) for c in sol])
    closest = sol * L
    
    # The short vector is the difference
    short_vec = closest - v
    sk_prime = abs(short_vec[1]) # sk_prime is the small component
    
    return Integer(sk_prime)

# --- Main Exploit Logic ---

io = remote(HOST, PORT)

# 1. Receive the first encrypted private key
io.recvuntil(b"Here is your encrypted signing key, use it to sign a message : ")
initial_data = json.loads(io.recvline())
pk1_x = int(initial_data['pubkey']['x'], 16)
pk1_y = int(initial_data['pubkey']['y'], 16)
signkey1 = bytes.fromhex(initial_data['signkey'])
tag1, ct1 = signkey1[:16], signkey1[16:]
log.info("Received first key and public key.")

# 2. Request a new key to get a second encryption with the same nonce
io.sendlineafter(b"> ", json.dumps({'option': 'generate_key'}).encode())
io.recvuntil(b"Here is your *NEW* encrypted signing key :\n") # Consume the newline!
new_data = json.loads(io.recvline())
pk2_x = int(new_data['pubkey']['x'], 16)
pk2_y = int(new_data['pubkey']['y'], 16)
signkey2 = bytes.fromhex(new_data['signkey'])
tag2, ct2 = signkey2[:16], signkey2[16:]
log.info("Received second key and public key.")

# 3. Solve for the GCM authentication key, H
H_candidates = solve_ghash_equation(ct1, tag1, ct2, ct2)
log.success(f"Found H candidates: {[hex(h) for h in H_candidates]}")

for H in H_candidates:
    with log.progress(f"Trying H = {hex(H)}") as p:
        # 4. Forge a ciphertext that decrypts to a key with top 128 bits zeroed
        # This makes the resulting key sk' small enough for the lattice attack
        delta = b'\xff' * 16 + b'\x00' * 16
        forged_ct = xor(ct1, delta)

        # Forge the corresponding tag
        S = ghash(H, ct1) ^ F.fetch_int(bytes_to_long(tag1))
        forged_tag_val = int(ghash(H, forged_ct) ^ S)
        forged_tag = long_to_bytes(forged_tag_val, 16)
        forged_signkey = forged_tag + forged_ct
        p.status("Forged ciphertext and tag")

        # 5. Request a signature using the forged key
        msg = b"find the key"
        z = bytes_to_long(hashlib.sha256(msg).digest())
        payload = {'option': 'sign', 'msg': msg.hex(), 'signkey': forged_signkey.hex()}
        io.sendlineafter(b"> ", json.dumps(payload).encode())
        
        sig_line = io.recvline()
        if b"error" in sig_line:
            p.failure("Signature failed. H might be wrong.")
            continue
        
        sig_data = json.loads(sig_line)
        r, s = int(sig_data['r'], 16), int(sig_data['s'], 16)
        p.status("Received signature with corrupted key")
        
        # 6. Recover the small corrupted key sk' via HNP
        sk_prime = recover_sk_hnp(r, s, z, q)
        p.status(f"Recovered corrupted key sk' = {sk_prime}")
        
        # 7. Recover the original private key sk1 from sk'
        p_prime = long_to_bytes(sk_prime, 32)
        p1 = xor(p_prime, delta)
        sk1 = bytes_to_long(p1)
        
        # 8. Verify sk1 is correct
        if sk1 * G == Point(pk1_x, pk1_y, curve=P256):
            p.success(f"Recovered sk1 correctly: {sk1}")
            
            # 9. Recover the current private key sk2
            p1_xor_p2 = xor(ct1, ct2)
            p2 = xor(p1, p1_xor_p2)
            sk2 = bytes_to_long(p2)
            log.success(f"Recovered sk2: {sk2}")

            # 10. Get and decrypt the flag
            io.sendlineafter(b"> ", json.dumps({'option': 'get_flag'}).encode())
            flag_data = json.loads(io.recvline())
            encrypted_flag = bytes.fromhex(flag_data['flag'])
            
            key = hashlib.sha256(long_to_bytes(sk2)).digest()[:16]
            from Crypto.Cipher import AES
            cipher = AES.new(key, AES.MODE_ECB)
            flag = cipher.decrypt(encrypted_flag)
            
            log.success(f"Flag: {flag.decode().strip()}")
            io.close()
            exit(0)
        else:
            p.failure("Verification of sk1 failed. Trying next H.")

io.close()
