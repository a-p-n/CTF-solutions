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
modulus_poly = x**128 + x**7 + x**2 + x + 1
F = GF(2**128, name='y', modulus=modulus_poly)

# --- Helper Functions ---

def solve_ghash_equation(c1, t1, c2, t2):
    """Solves the cubic equation for the GCM authentication key H."""
    if len(c1) != 32 or len(c2) != 32:
        log.error("Ciphertexts must be 32 bytes long for this solver.")
        return []

    delta1 = F.fetch_int(bytes_to_long(c1[:16]) ^ bytes_to_long(c2[:16]))
    delta2 = F.fetch_int(bytes_to_long(c1[16:]) ^ bytes_to_long(c2[16:]))
    delta_tag = F.fetch_int(bytes_to_long(t1) ^ bytes_to_long(t2))

    Poly, H = PolynomialRing(F, 'H').objgen()
    eqn = delta1 * H**3 + delta2 * H**2 + delta_tag
    roots = eqn.roots(multiplicities=False)

    if not roots:
        return []
    return [r._integer_representation() for r in roots]

def ghash(H_val, ct):
    """Computes the GHASH for a given ciphertext and H, including length block."""
    H = F.fetch_int(H_val)
    res = F.zero()
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    for block in blocks:
        res += F.fetch_int(bytes_to_long(block))
        res *= H
        
    # *** THIS IS THE CORRECTED LINE ***
    # The length block is len(AAD) || len(ciphertext) in bits.
    # len(AAD) = 0, len(ciphertext) = 32 bytes = 256 bits.
    length_block = F.fetch_int(256)
    res += length_block
    res *= H
    return res

def recover_sk_hnp(r, s, z, order):
    """Recovers a small secret key using lattice reduction (solves HNP)."""
    s_inv = inverse(s, order)
    C1 = (r * s_inv) % order
    C2 = (z * s_inv) % order

    L = Matrix(ZZ, [[order, 0], [C1, 1]])
    v = vector(ZZ, [C2, 0])

    sol = L.solve_left(v)
    sol = vector([round(c) for c in sol])
    closest = sol * L

    short_vec = closest - v
    sk_prime = abs(short_vec[1])

    return int(sk_prime)

# --- Main Exploit Logic ---

io = remote(HOST, PORT)

try:
    io.recvuntil(b"Here is your encrypted signing key, use it to sign a message : ")
    initial_data = json.loads(io.recvline().decode())
    pk1_x, pk1_y = int(initial_data['pubkey']['x'], 16), int(initial_data['pubkey']['y'], 16)
    signkey1 = bytes.fromhex(initial_data['signkey'])
    tag1, ct1 = signkey1[:16], signkey1[16:]
    log.info("Received first key.")

    io.sendlineafter(b"> ", json.dumps({'option': 'generate_key'}).encode())
    io.recvuntil(b"Here is your *NEW* encrypted signing key :\n")
    new_data = json.loads(io.recvline().decode())
    pk2_x, pk2_y = int(new_data['pubkey']['x'], 16), int(new_data['pubkey']['y'], 16)
    signkey2 = bytes.fromhex(new_data['signkey'])
    tag2, ct2 = signkey2[:16], signkey2[16:]
    log.info("Received second key.")

    H_candidates = solve_ghash_equation(ct1, tag1, ct2, tag2)
    if not H_candidates:
        log.error("Could not find H. Please try running the script again.")
        exit(1)
    log.success(f"Found H candidates: {[hex(h) for h in H_candidates]}")

    for H in H_candidates:
        with log.progress(f"Trying H = {hex(H)}") as p:
            delta = b'\xff' * 16 + b'\x00' * 16
            forged_ct = xor(ct1, delta)

            S = ghash(H, ct1) ^ F.fetch_int(bytes_to_long(tag1))
            forged_tag_val = int(ghash(H, forged_ct) ^ S)
            forged_tag = long_to_bytes(forged_tag_val, 16)
            forged_signkey = forged_tag + forged_ct
            p.status("Forged ciphertext and tag")

            msg = b"find the key"
            z = bytes_to_long(hashlib.sha256(msg).digest())
            payload = {'option': 'sign', 'msg': msg.hex(), 'signkey': forged_signkey.hex()}
            io.sendlineafter(b"> ", json.dumps(payload).encode())

            sig_line = io.recvline().decode()
            if "error" in sig_line:
                p.failure("Signature failed. H might be wrong.")
                continue

            sig_data = json.loads(sig_line)
            r, s = int(sig_data['r'], 16), int(sig_data['s'], 16)
            p.status("Received signature with corrupted key")

            sk_prime = recover_sk_hnp(r, s, z, q)
            p.status(f"Recovered corrupted key sk' = {sk_prime}")

            p_prime = long_to_bytes(sk_prime, 32)
            p1 = xor(p_prime, delta)
            sk1 = bytes_to_long(p1)

            if sk1 * G == Point(pk1_x, pk1_y, curve=P256):
                p.success("Recovered sk1 correctly!")
                
                p1_xor_p2 = xor(ct1, ct2)
                p2 = xor(p1, p1_xor_p2)
                sk2 = bytes_to_long(p2)
                log.success("Recovered sk2!")

                io.sendlineafter(b"> ", json.dumps({'option': 'get_flag'}).encode())
                flag_data = json.loads(io.recvline().decode())
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

except Exception as e:
    log.error(f"An unexpected error occurred: {str(e)}")
finally:
    io.close()
