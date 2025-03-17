from sage.all import *

# This is the given function from the challenge
def numberToBase(n, b):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits[::-1]

# Function to get sum of digits in a given base (for testing without server)
def get_digit_sum(num, base):
    digits = numberToBase(num, base)
    return sum(digits)

# This function simulates the server's response
def simulate_server(flag_int, base):
    return sum(numberToBase(flag_int, base))

# Function to connect to the actual server (replace this with real connection code)
def connect_to_server(base, host, port):
    # In a real scenario, you would connect to the server here
    # For testing, we'll simulate with a dummy flag
    dummy_flag = b"FLAG{dummy_flag_for_testing_LLL_approach}"
    dummy_flag_int = int.from_bytes(dummy_flag, 'big')
    return simulate_server(dummy_flag_int, base)

# The key insight: for a number n in base b, the remainder when divided by (b-1)
# is the same as the remainder of the sum of its digits when divided by (b-1)
# This is known as the digit sum property

def recover_flag_using_lll():
    # In a real scenario, replace this with real connections
    # For testing, we'll create a simulated flag
    flag_bytes = b"FLAG{test_flag_for_LLL_recovery_demo}"
    flag_int = int.from_bytes(flag_bytes, 'big')
    
    print(f"Testing with flag: {flag_bytes}")
    print(f"Flag as integer: {flag_int}")
    
    # Collect congruence relations from different bases
    relations = []
    moduli = []
    
    # Choose bases that are relatively prime to each other
    # to maximize the information we get
    bases = []
    for b in range(3, 100):
        # Skip if b-1 shares factors with our existing moduli
        mod = b - 1
        if all(gcd(mod, m) == 1 for m in moduli):
            bases.append(b)
            moduli.append(mod)
            if len(bases) >= 30:  # 30 relations should be enough
                break
    
    print(f"Using bases: {bases}")
    
    # Collect relations
    for base in bases:
        digit_sum = simulate_server(flag_int, base)
        # By the digit sum property, flag_int ≡ digit_sum (mod base-1)
        relations.append((digit_sum, base - 1))
        print(f"Base {base}: Sum = {digit_sum}, Mod = {base-1}")
    
    # Set up lattice for LLL
    n = len(relations)
    lattice_dim = n + 1
    
    # Create the lattice matrix
    L = matrix(ZZ, lattice_dim, lattice_dim)
    
    # We use the approach described in the Howgrave-Graham paper for LLL-based CRT
    bound = 2^(45 * 8)  # Upper bound for the flag (45 bytes max)
    
    # Set up the lattice rows
    for i in range(n):
        L[i, i] = relations[i][1]  # The modulus (base-1)
        L[i, n] = relations[i][0]  # The remainder (digit sum)
    
    # The last row represents our target
    scaling_factor = max(moduli) * n  # Scale to make sure this row is reduced
    L[n, n] = scaling_factor
    
    # Apply LLL to find short vectors
    L_reduced = L.LLL()
    
    # The shortest vector should give us information about the flag
    potential_flags = []
    
    for row in L_reduced:
        # Check if this could be a valid solution
        candidate = row[n]
        
        # Verify the congruence relations
        valid = True
        for (digit_sum, modulus) in relations:
            if candidate % modulus != digit_sum % modulus:
                valid = False
                break
        
        if valid and 0 < candidate < bound:
            potential_flags.append(candidate)
    
    # Check the potential flags
    for candidate in potential_flags:
        try:
            # Calculate byte length needed
            byte_length = (candidate.bit_length() + 7) // 8
            if byte_length <= 45:  # Check against the max length constraint
                flag_candidate = candidate.to_bytes(byte_length, 'big')
                
                # Check if this has printable ASCII characters
                if all(32 <= c < 127 for c in flag_candidate):
                    print(f"Potential flag: {flag_candidate}")
                    print(f"Decoded: {flag_candidate.decode()}")
                    
                    # Verify this matches our test digit sums
                    verification = True
                    for base in bases:
                        expected = simulate_server(candidate, base)
                        actual = simulate_server(flag_int, base)
                        if expected != actual:
                            verification = False
                            print(f"Failed verification for base {base}")
                            break
                    
                    if verification:
                        print("✅ Verified: This matches all digit sums!")
                    else:
                        print("❌ Failed: This doesn't match all digit sums")
        except:
            pass  # Skip invalid byte sequences

    # If we don't find a solution with the first approach, try a more direct method
    # using Chinese Remainder Theorem (CRT)
    if not potential_flags:
        print("Trying alternative approach with CRT...")
        crt_moduli = []
        crt_remainders = []
        
        for digit_sum, modulus in relations:
            if gcd(modulus, prod(crt_moduli) if crt_moduli else 1) == 1:
                crt_moduli.append(modulus)
                crt_remainders.append(digit_sum % modulus)
        
        try:
            # Use CRT to find a solution
            solution = crt(crt_remainders, crt_moduli)
            
            # We get congruence mod product of moduli, but we need actual flag value
            mod_product = prod(crt_moduli)
            
            # Try different possibilities
            for k in range(100):
                candidate = solution + k * mod_product
                if candidate < bound:
                    try:
                        byte_length = (candidate.bit_length() + 7) // 8
                        if byte_length <= 45:
                            flag_candidate = candidate.to_bytes(byte_length, 'big')
                            if all(32 <= c < 127 for c in flag_candidate):
                                print(f"CRT solution: {flag_candidate}")
                                print(f"Decoded: {flag_candidate.decode()}")
                    except:
                        pass
        except:
            print("CRT approach failed")

# Run the solver
recover_flag_using_lll()