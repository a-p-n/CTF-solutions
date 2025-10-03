#!/usr/bin/env sage

from pwn import *
from sage.all import *
from tqdm import trange

# Helper functions for byte/bit conversions
def bitify(inpt):
    ans = []
    for c in inpt:
        for i in range(8):
            ans.append((c >> i) & 1)
    return vector(GF(2), ans)

def unbitify(inpt):
    ans = []
    for i in range(0, len(inpt), 8):
        c = 0
        for j in range(8):
            c += pow(2, j) * int(inpt[j + i])
        ans.append(c)
    return bytes(ans)

# --- Oracle Communication ---
conn = remote("smol-aes.chal.crewc.tf", 1337)
conn.recvline()
context.log_level = 'debug'
def get_enc(pt_hex):
    conn.recvline()
    conn.sendlineafter(b"> ", pt_hex.encode())
    conn.recvuntil(b"Ciphertext : ")
    return conn.recvline().strip().decode()

# --- Step 1: Recover Final S-box Layer (S2_inv) ---
print("[+] Recovering final S-box layer (S2_inv)...")
S2_inv = []
for sbox_idx in range(8):
    print(f"  [-] Recovering S2_inv[{sbox_idx}]...")
    
    # We need 255 * 8 = 2040 equations to solve for the 256 * 8 variables of the S-box inverse table
    # Each plaintext set gives 8 linear equations. 255 sets are enough.
    
    R = PolynomialRing(GF(2), [f"x_{i}_{j}" for i in range(256) for j in range(8)])
    eqs = []
    
    for i in trange(255):
        outputs = []
        for j in range(256):
            pt = b'\x00' * 8
            pt_list = list(pt)
            pt_list[0] = j  # Vary first byte
            pt_list[1] = i  # Use i as the constant part
            pt = bytes(pt_list)
            
            ct = bytes.fromhex(get_enc(pt.hex()))
            outputs.append(ct[sbox_idx])

        # For each of the 8 bits, the XOR sum must be 0
        for bit_idx in range(8):
            current_eq = 0
            for val in outputs:
                # Add the variable representing the bit of the S-box inverse output
                current_eq += R.gens()[val * 8 + bit_idx]
            eqs.append(current_eq)

    # Solve the system of linear equations
    b = vector(GF(2), [0] * len(eqs))
    A = matrix(GF(2), len(eqs), len(R.gens()), [[e.coefficient(v) for v in R.gens()] for e in eqs])
    
    sol = A.solve_right(b)
    
    # Reconstruct the inverse S-box table
    sbox_inv_table = [0] * 256
    for i in range(256):
        val = 0
        for j in range(8):
            val += sol[i * 8 + j] * (2**j)
        sbox_inv_table[i] = val
    S2_inv.append(sbox_inv_table)

print("[+] S2_inv recovered successfully!")

def apply_sbox_inv(inpt, sbox_inv_list):
    res = b""
    for char, sbox_inv in zip(inpt, sbox_inv_list):
        res += bytes([sbox_inv[char]])
    return res

# --- Step 2: Recover Linear Layer (L_rec) ---
print("[+] Recovering linear layer L...")
L_rows = []
for i in range(64):
    pt = bytearray(8)
    # Create a plaintext that activates a single bit after the first S-box layer
    # Since we don't know S1, we find an input that produces a single bit output.
    # A simpler way that works is to find the row space.
    
# Alternative (and simpler) approach: find the row spaces
L_basis_rows = []
for i in range(8): # For each input byte
    basis = []
    # Get outputs for a basis of the input space + the zero vector
    y0_hex = get_enc(('00' * 8))
    y0 = bitify(apply_sbox_inv(bytes.fromhex(y0_hex), S2_inv))
    
    for j in range(8): # For each bit in the byte
        pt = bytearray(8)
        pt[i] = 1 << j
        y_hex = get_enc(bytes(pt).hex())
        y = bitify(apply_sbox_inv(bytes.fromhex(y_hex), S2_inv))
        basis.append(y - y0)
    L_basis_rows.extend(basis)

L_rec = matrix(GF(2), L_basis_rows).inverse()
print("[+] L_rec recovered successfully!")

# --- Step 3: Recover First S-box Layer (S1) ---
print("[+] Recovering first S-box layer (S1)...")
S1 = []
for sbox_idx in range(8):
    sbox_table = [0] * 256
    for val in range(256):
        pt = bytearray(8)
        pt[sbox_idx] = val
        ct = bytes.fromhex(get_enc(bytes(pt).hex()))
        
        intermediate = apply_sbox_inv(ct, S2_inv)
        s1_out_vec = bitify(intermediate) * L_rec
        s1_out_bytes = unbitify(s1_out_vec)
        sbox_table[val] = s1_out_bytes[sbox_idx]
    S1.append(sbox_table)

# We need the inverse for decryption
S1_inv = []
for sbox_table in S1:
    sbox_inv_table = [0] * 256
    for i, val in enumerate(sbox_table):
        sbox_inv_table[val] = i
    S1_inv.append(sbox_inv_table)

print("[+] S1_inv recovered successfully!")
conn.sendline(b"-1") # End oracle phase

# --- Step 4: Solve the Challenges ---
print("[+] All key components recovered. Solving challenges...")

def decrypt_block(ct, s1_inv, l_inv, s2_inv):
    intermediate1 = apply_sbox_inv(ct, s2_inv)
    intermediate2 = unbitify(bitify(intermediate1) * l_inv)
    pt = apply_sbox_inv(intermediate2, s1_inv)
    return pt

for i in range(30):
    conn.recvuntil(b"Encrypted secret: ")
    ct_hex = conn.recvline().strip().decode()
    ct = bytes.fromhex(ct_hex)
    
    pt = decrypt_block(ct, S1_inv, L_rec, S2_inv)
    
    conn.sendlineafter(b"> ", pt.hex().encode())
    print(f"  [-] Solved challenge {i+1}/30: {ct.hex()} -> {pt.hex()}")

print("[+] All challenges solved!")
conn.interactive()