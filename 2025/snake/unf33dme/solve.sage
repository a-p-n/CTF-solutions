from Crypto.Hash import SHAKE256
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

p = 65537
nbytes = p.bit_length() // 8
state_size = 24
rounds = 3
exp = 3

digest_list = [59575, 39554, 20426, 26892, 14244, 34928, 8912, 25395, 35425, 43937, 37925, 39253, 26985, 11011, 24090, 37573, 34874, 4300, 58928, 38274, 683, 14478, 19404, 52736]
IV_list = [2392, 28114, 57683, 23451, 60401, 25807, 25047, 61339, 10364, 38073, 49228, 59995, 51036, 54179, 37706, 56877, 8731, 59000, 50296, 23914, 674, 37111, 15338, 19670]

F = GF(p)
R = PolynomialRing(F, 'x')
x = R.gen()

shake = SHAKE256.new()
shake.update(b"SNAKECTF")
constants = [F(int.from_bytes(shake.read(nbytes), 'big')) for _ in range(rounds)]
C0, C1, C2 = constants

D = [F(d) for d in digest_list]
IV = [F(iv) for iv in IV_list]

def permute_element(var, iv_val):
    s = (((var + iv_val)^exp + C0)^exp + C1)^exp + C2
    return s

P = [F(0)] * state_size

print("Solving the 12 systems of polynomial equations...")

for i in range(0, state_size, 2):
    Di, Di1 = D[i], D[i+1]
    IVi, IVi1 = IV[i], IV[i+1]

    perm_x = permute_element(x, IVi)
    
    p_i_plus_1_expr = Di - perm_x
    
    poly_eq = permute_element(p_i_plus_1_expr, IVi1) + x - Di1

    roots = poly_eq.roots(multiplicities=False)
    print(roots)
    if not roots:
        print(f"Error: No solution found for P[{i}]")
        exit(1)
    
    p_i_sol = roots[0]
    
    p_i_plus_1_sol = Di - permute_element(p_i_sol, IVi)
    
    P[i] = p_i_sol
    P[i+1] = p_i_plus_1_sol

print("✅ All systems solved!")

padded_message = b"".join([long_to_bytes(int(val), nbytes) for val in P])

# 2. Unpad the message using the correct block size
block_size = state_size * nbytes
flag_bytes = unpad(padded_message, block_size)

# 3. Decode the final bytes to get the readable flag
flag = flag_bytes.decode()

print("\n🚩 The recovered flag is:")
print(flag)