#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import inverse, long_to_bytes
import random
from collections import Counter
import z3

# --- Server functions copied for local simulation ---

bits = 512

def generate_random_shuffle(seed, splits):
    random.seed(seed)
    lst = list(range(bits))
    caca = [lst[j:j+splits] for j in range(0,len(lst),splits)]
    for chunk in caca:
        random.shuffle(chunk)
    # The list comprehension was buggy in the original code, this is the correct flattening
    return [item for sublist in caca for item in sublist]

# --- Our Utility Functions ---

def get_xored_sum_for_seed(seed):
    """Calculates the deterministic part of the narnia output for a single seed."""
    xored = 0
    seed_count = 20
    random.seed(seed)
    arr = [random.randint(0, 2**32 - 1) for _ in range(seed_count)]
    for i in range(len(arr)):
        xored ^= arr[i]
    return xored

def recover_seed(p, query_type):
    """Recovers a secret seed (seedx or seedy) using a statistical attack."""
    log.info(f"Attempting to recover seed for '{query_type}'...")
    
    # Use a fixed set of seeds for all queries
    seeds = [1, 2, 3, 4, 5]
    seeds_str = " ".join(map(str, seeds))
    
    # Calculate the known, deterministic part of the XOR sum
    known_part = 0
    for seed in seeds:
        known_part ^= get_xored_sum_for_seed(seed)

    # Make multiple queries to find the most common output
    responses = []
    # Query limit is 42, we use 20 for each seed.
    for i in range(20):
        p.sendline(f"query {query_type} {seeds_str}".encode())
        response = p.recvline().decode().strip()
        output = int(response.split(": ")[1])
        # We are interested in `secret ^ random_part`
        responses.append(output ^ known_part)

    # The most common value is our best guess for the secret
    # This assumes the most probable random part is 0
    data = Counter(responses)
    recovered = data.most_common(1)[0][0]
    log.success(f"Recovered seed for '{query_type}': {recovered}")
    return recovered

def unshuffle_chunk(val, shuffle_arr):
    """Reverses the shuffle_chunk operation."""
    res = 0
    for i in range(bits):
        if (val >> shuffle_arr[i]) & 1:
            res |= 1 << i
    return res

def recover_seed_candidates(p, query_type, num_candidates=3):
    """Recovers the top N most likely secret seed candidates."""
    log.info(f"Attempting to recover top {num_candidates} candidates for '{query_type}'...")
    
    seeds = [1, 2, 3, 4, 5]
    seeds_str = " ".join(map(str, seeds))
    
    known_part = 0
    for seed in seeds:
        known_part ^= get_xored_sum_for_seed(seed)

    responses = []
    # Use 21 queries to maximize data from the 42 query limit
    for i in range(21):
        p.sendline(f"query {query_type} {seeds_str}".encode())
        response = p.recvline().decode().strip()
        output = int(response.split(": ")[1])
        responses.append(output ^ known_part)

    data = Counter(responses)
    # Get the N most common potential secrets (the first element of the tuple)
    candidates = [item[0] for item in data.most_common(num_candidates)]
    log.success(f"Found potential candidates for '{query_type}': {candidates}")
    return candidates

# --- Main Exploit Logic ---

p = remote("34.89.179.154", 30851)


# 1. Get initial data from the server
log.info("Requesting initial data...")
p.sendline(b"get_data")
p.recvuntil(b"n = ")
n = int(p.recvline().strip())
p.recvuntil(b"leak = ")
leak = int(p.recvline().strip())
p.recvuntil(b"sefu_la_bani = ")
p.recvline() # Discard this line
p.recvuntil(b"cei_ce_au_valoarea = ")
p.recvline() # Discard this line
p.recvuntil(b"k = ")
p.recvline() # Discard this line
p.recvuntil(b"ct = ")
ct = int(p.recvline().strip())
log.success("Received data.")
log.info(f"n = {n}")
log.info(f"leak = {leak}")
log.info(f"ct = {ct}")

seedx_candidates = recover_seed_candidates(p, "x", 3)
seedy_candidates = recover_seed_candidates(p, "y", 3)

p.close()

# 3. Iterate through all 9 pairs and test with Z3
p_val, q_val = None, None
found = False

for idx, seedx in enumerate(seedx_candidates):
    for idy, seedy in enumerate(seedy_candidates):
        log.info(f"Testing pair ({idx+1}/3, {idy+1}/3): seedx={seedx}, seedy={seedy}")
        
        # Reconstruct shuffle arrays for the current candidate pair
        x_shuffle = generate_random_shuffle(seedx, 13)
        y_shuffle = generate_random_shuffle(seedy, 7)

        # Set up and run the Z3 solver
        p_shuffled = z3.BitVec('p_shuffled', bits)
        p_unshuffled = z3.BitVec('p', bits)
        q_unshuffled = z3.BitVec('q', bits)
        q_shuffled = p_shuffled ^ leak

        solver = z3.Solver()
        # Set a timeout for the solver (e.g., 2 minutes) to avoid getting stuck
        solver.set("timeout", 120000) 

        for i in range(bits):
            solver.add(z3.Extract(i, i, p_unshuffled) == z3.Extract(x_shuffle[i], x_shuffle[i], p_shuffled))
            solver.add(z3.Extract(i, i, q_unshuffled) == z3.Extract(y_shuffle[i], y_shuffle[i], q_shuffled))

        solver.add(z3.Extract(bits - 1, bits - 1, p_unshuffled) == 1)
        solver.add(z3.Extract(0, 0, p_unshuffled) == 1)
        solver.add(z3.Extract(bits - 1, bits - 1, q_unshuffled) == 1)
        solver.add(z3.Extract(0, 0, q_unshuffled) == 1)
        solver.add(p_unshuffled * q_unshuffled == n)

        if solver.check() == z3.sat:
            log.success("Z3 found a solution!")
            model = solver.model()
            p_val = model[p_unshuffled].as_long()
            q_val = model[q_unshuffled].as_long()
            
            if p_val * q_val == n:
                log.success(f"Correct seeds found: seedx={seedx}, seedy={seedy}")
                found = True
                break
            else:
                log.warning("Z3 solution was incorrect, continuing...")
    if found:
        break

if not found:
    log.error("Could not find the correct seeds among the top candidates. The server may be very unlucky.")
    exit()

# 5. Decrypt the flag
log.info(f"p = {p_val}")
log.info(f"q = {q_val}")
e = 65537
phi = (p_val - 1) * (q_val - 1)
d = inverse(e, phi)
pt = pow(ct, d, n)

flag = long_to_bytes(pt)
log.success(f"Flag: {flag.decode()}")

p.close()