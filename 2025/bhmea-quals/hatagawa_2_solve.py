#!/usr/bin/env python3
from pwn import *
from z3 import *

# --- Connection Details for Hatagawa II ---
HOST = "34.252.33.37"
PORT = 30421

# The state advances by 3 steps for each encryption for a 16-byte content.
STATE_ADVANCE = 3
# We will use 4 ciphertexts to ensure the Z3 solution is unique.
CIPHERTEXT_COUNT = 4

def get_ciphertexts(n=CIPHERTEXT_COUNT):
    """Connects ONCE and gets n ciphertexts."""
    conn = remote(HOST, PORT)
    ciphertexts = []
    print(f"[*] Getting {n} ciphertexts from one connection...")
    for i in range(n):
        conn.recvuntil(b'> ')
        conn.sendline(b's')
        conn.recvuntil(b'BHFlagY{')
        hex_ct = conn.recvuntil(b'}', drop=True).strip().decode()
        # The received ciphertext is 32 hex chars -> 16 bytes
        if len(hex_ct) != 32:
            print(f"[-] Error: Unexpected ciphertext length ({len(hex_ct)}). Exiting.")
            exit(1)
        ciphertexts.append(bytes.fromhex(hex_ct))
        print(f"  [+] Got ciphertext {i+1}/{n}")
    conn.close()
    print("[+] Ciphertexts collected.")
    return ciphertexts

def solve_lcg_from_xor(cts):
    """Uses Z3 to solve for LCG params, assuming the true modulus is 2**64."""
    print("[*] Using Z3 with the corrected mod 2**64 model...")

    MOD_PARAM_GEN = 2**64 - 1 # This is only for parameter generation constraints
    
    a, c = BitVecs('a c', 64)
    num_states_needed = STATE_ADVANCE * len(cts)
    states = [BitVec(f'x{i}', 64) for i in range(1, num_states_needed + 1)]

    solver = Solver()

    # 1. LCG state progression: TRUSTING THE EVIDENCE from the Part 1 solve.
    # The LCG is a standard mod 2**64. Z3's BitVec arithmetic handles this implicitly.
    print("[*] Applying standard LCG rule: x_next = (a*x + c) mod 2**64")
    for i in range(len(states) - 1):
        solver.add(states[i+1] == a * states[i] + c)

    # 2. Add XOR constraints from multiple ciphertext pairs
    print("[*] Adding XOR constraints from all pairs...")
    for i in range(len(cts) - 1):
        c_current, c_next = cts[i], cts[i+1]
        k_diff = xor(c_current, c_next)
        k_diff_chunks = [int.from_bytes(k_diff[j:j+8], 'big') for j in range(0, len(k_diff), 8)]

        for chunk_idx, chunk_val in enumerate(k_diff_chunks):
            state_idx1 = i * STATE_ADVANCE + chunk_idx
            state_idx2 = (i + 1) * STATE_ADVANCE + chunk_idx
            solver.add(states[state_idx1] ^ states[state_idx2] == chunk_val)

    # 3. Add parameter constraints from the source code
    print("[*] Adding parameter constraints...")
    solver.add(a & 7 == 5)
    solver.add(c & 1 == 1)
    solver.add(ULE(c, MOD_PARAM_GEN - 1))
    a_max_rand_part = (MOD_PARAM_GEN >> 3) - 1
    a_max = (a_max_rand_part << 3) | 5
    solver.add(ULE(a, a_max))

    if solver.check() == sat:
        print("[+] Z3 found a solution! ✅")
        model = solver.model()
        return (model[a].as_long(), model[c].as_long(), model[states[0]].as_long())
    else:
        print("[-] Z3 could not find a solution.")
        return None, None, None

# --- Main Exploit Logic ---
ciphertexts = get_ciphertexts()
c1 = ciphertexts[0]

a, c, x1_val = solve_lcg_from_xor(ciphertexts)
if a is None:
    exit(1)

print(f"[*] Cracked Parameters:\n  a = {hex(a)}\n  c = {hex(c)}\n  x1 = {hex(x1_val)}")

m_op = 1 << 64
x = x1_val 

keystream1 = b''
num_chunks = (len(c1) + 7) // 8

for i in range(num_chunks):
    if i > 0:
        x = (a * x + c) % m_op # Using the correct mod 2**64 rule
    keystream1 += x.to_bytes(8, 'big')

plaintext_content = xor(c1, keystream1[:len(c1)])
flag = b'BHFlagY{' + plaintext_content.hex().encode() + b'}'

print(f"\n[!] FLAG: {flag.decode()}\n")