#!/usr/bin/env python3
from pwn import *
from sympy import factorint
from tqdm import trange

# Set up the connection to the challenge server
# conn = remote('epow.chal.crewc.tf', 1337, ssl=True)
# For demonstration, we'll use a local process if the remote is down.
# To run this script, you must connect to the actual server.
# This is a placeholder for explaining the logic.

def solve_pow(conn):
    """
    Solves one round of the EPOW challenge.
    """
    try:
        # Receive the line with the salt, e.g., "..., the salt is: deadbeef..."
        conn.recvline()
        line = conn.recvline().decode()
        log.info(line.strip())
        
        # Extract the hex-encoded salt
        salt_hex = line.split(":")[-1].strip()
        m = bytes.fromhex(salt_hex)
        
        # Iterate through all 256 possible values for the first byte
        for x_val in trange(256):
            X = x_val.to_bytes(1, 'big')
            
            # Construct the integer A by concatenating X and the salt m
            A = int.from_bytes(X + m, 'big')
            
            # Find the prime factors of A using sympy's factorint
            factors = factorint(A)
            
            # Check each prime factor against the challenge's conditions
            for p, exp in factors.items():
                # Condition 1: Prime p must be within the specified bit length
                # Condition 2: Prime p must be congruent to 3 mod 4
                if 384 <= p.bit_length() <= 640 and p % 4 == 3:
                    log.success(f"Found solution byte X: {X.hex()}")
                    log.success(f"Found suitable prime p: {p}")
                    
                    # Send our byte X (hex-encoded)
                    conn.sendlineafter(b'> ', X.hex().encode())
                    
                    # Send our prime p
                    conn.sendlineafter(b'> ', str(p).encode())
                    
                    # We found a solution, so we can exit the loops and solve the next round
                    return

    except EOFError:
        log.error("Connection closed unexpectedly.")
        exit()

# Main execution logic
if __name__ == "__main__":
    # Connect to the remote server
    with remote('epow.chal.crewc.tf', 1337, ssl=True) as conn:
        # The challenge requires solving 10 rounds
        num_rounds = 10
        for i in range(num_rounds):
            solve_pow(conn)
        
        # After 10 successful rounds, the server sends the flag
        flag = conn.recvall().decode()
        log.success(f"Flag: {flag.strip()}")