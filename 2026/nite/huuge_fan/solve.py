import ast
from hashlib import sha256
from sage.all import *
import Crypto.Util.number

m = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D
m_str = str(m)
m_len = len(m_str)

B = int(m_str[:4]) 
SUFFIX_LEN = m_len - 4
SHIFT = 10**SUFFIX_LEN

print(f"Modulus m: {m}")
print(f"Modulus bits: {m.bit_length()}")
print(f"Base B: {B}")
print(f"Shift: 10^{SUFFIX_LEN}")
print(f"Estimated error bound: 2^{SHIFT.bit_length()}")

def parse_recordings(content):
    content = content.replace('\n', '').replace(' ', '')
    for i in range(1, 10):
        content = content.replace(f'', '')
        
    try:
        data = ast.literal_eval(content)
        return data
    except:
        print("Parsing error. Ensure out.txt contains the valid python list structure.")
        return []

def recover_v(n):
    factors_list = list(factor(n))
    
    all_divisors = [1]
    for p, e in factors_list:
        new_divs = []
        for d in all_divisors:
            for i in range(e + 1):
                new_divs.append(d * (p**i))
        all_divisors = new_divs
    
    for d in all_divisors:
        if d >= B**5: continue
        
        temp_d = d
        digits = []
        for _ in range(5):
            digits.append(temp_d % B)
            temp_d //= B
        
        v_cand = digits[::-1]
        
        if v_cand != sorted(v_cand): continue
            
        d2 = n // d
        temp_d2 = d2
        digits2 = []
        for _ in range(5):
            digits2.append(temp_d2 % B)
            temp_d2 //= B
            
        if digits2 == v_cand:
            return v_cand
    return None

def solve_hnp_eliminated(samples):
    N = len(samples)
    
    inv_alphas = []
    constants = []
    
    a0, b0 = samples[0]
    inv_a0 = inverse_mod(a0, m)
    term0 = (inv_a0 * b0) % m
    
    inv_alphas.append(inv_a0)
    
    for i in range(1, N):
        ai, bi = samples[i]
        inv_ai = inverse_mod(ai, m)
        term_i = (inv_ai * bi) % m
        
        K_i = (term0 - term_i) % m
        inv_alphas.append(inv_ai)
        constants.append(K_i)
        
    scale = 2**446
    M = Matrix(ZZ, N + 1, N + 1)
    
    inv_a0 = inverse_mod(samples[0][0], m)
    
    for i in range(1, N):
        alpha_i, beta_i = samples[i]
        T_i = (alpha_i * inv_a0) % m
        C_i = (beta_i - T_i * samples[0][1]) % m
        
        M[i, i] = m
        M[0, i] = T_i
        M[N, i] = C_i
        
    M[0, 0] = 1
    M[N, N] = scale
    
    print("Time for LLL")
    L = M.LLL()
    
    for row in L:
        if abs(row[N]) == scale:
            eps_0 = row[0]
            
            if row[N] < 0: eps_0 = -eps_0
            
            d_cand = (inv_a0 * (eps_0 - samples[0][1])) % m
            return d_cand
            
    return None

with open("out.txt", "r") as f:
    raw_content = f.read()

recordings = parse_recordings(raw_content)

hnp_samples = []

for batch_idx, (n_val, signs) in enumerate(recordings):
    v_digits = recover_v(n_val)
    if v_digits is None: continue
        
    for j, (msg_hex, r_val, s_val) in enumerate(signs):
        msg = bytes.fromhex(msg_hex)
        z_val = int.from_bytes(sha256(msg).digest(), 'big')
        
        a = v_digits[j] * SHIFT
        known_part = a + (SHIFT // 2)
        
        s_inv = inverse_mod(s_val, m)
        alpha = (s_inv * r_val) % m
        beta = (s_inv * z_val - known_part) % m
        
        hnp_samples.append((alpha, beta))

d_recovered = solve_hnp_eliminated(hnp_samples[:50])

if d_recovered:
    print(f"d = {d_recovered}")
    try:
        flag = Crypto.Util.number.long_to_bytes(d_recovered)
        print("Flag = ", flag)
    except:
        print("Could not convert d to bytes.")
else:
    print("Attack failed.")
