from Crypto.Hash import SHAKE256
from Crypto.Util.number import long_to_bytes
from sage.all import GF, PolynomialRing, inverse_mod
# Parameters
p = 65537
F = GF(p)
state_size = 24
nbytes = p.bit_length() // 8  # 2 bytes
rounds = 3
exp = 3

# Given digest and IV from out.txt
digest = [59575, 39554, 20426, 26892, 14244, 34928, 8912, 25395, 35425, 43937, 37925, 39253, 26985, 11011, 24090, 37573, 34874, 4300, 58928, 38274, 683, 14478, 19404, 52736]
IV = [2392, 28114, 57683, 23451, 60401, 25807, 25047, 61339, 10364, 38073, 49228, 59995, 51036, 54179, 37706, 56877, 8731, 59000, 50296, 23914, 674, 37111, 15338, 19670]

# Convert to finite field
digest = [F(x) for x in digest]
IV = [F(x) for x in IV]

# Generate constants
shake = SHAKE256.new()
shake.update(b"SNAKECTF")
constants = []
for _ in range(rounds):
    constants.append(F(int.from_bytes(shake.read(nbytes), 'big')))

# Compute inverse exponent for s-box
# s-box is x^3, so inverse is x^(3^-1 mod 65536)
inv_exp = inverse_mod(exp, p - 1)  # 3^-1 mod 65536

# Invert s-box
def inv_sbox(state):
    return [x^inv_exp for x in state]

# Invert add
def inv_add(state, constant):
    return [x - constant for x in state]

# Invert permute
def inv_permute(output):
    state = output
    for r in reversed(range(rounds)):
        state = inv_add(state, constants[r])
        state = inv_sbox(state)
    return state

# Invert shuffle
def unshuffle(state):
    result = state[:]
    for i in range(0, state_size, 2):
        result[i], result[i + 1] = result[i + 1], result[i]
    return result

# Step 1: Compute output by inverting permute
# We need to find output such that digest = output + shuffle(input)
# First, try to find input by assuming output = permute(input, IV)
state_0 = inv_permute(digest)  # This gives input + IV
input_guess = [state_0[i] - IV[i] for i in range(state_size)]

# Step 2: Compute shuffle(input) from digest and output
# Since digest = output + shuffle(input), we need output
# Let's try to find input by checking if input_guess is correct
# Recompute output = permute(input_guess, IV)
def permute(state, key):
    state = [state[i] + key[i] for i in range(state_size)]
    for r in range(rounds):
        state = [x^exp for x in state]
        state = [state[i] + constants[r] for i in range(state_size)]
    return state

output = permute(input_guess, IV)
shuffled_input = [digest[i] - output[i] for i in range(state_size)]

# Step 3: Unshuffle to get input
input_recovered = unshuffle(shuffled_input)

# Step 4: Convert input to bytes
flag_bytes = b""
for x in input_recovered:
    # Convert each field element to 2 bytes
    x_int = int(x)
    flag_bytes += long_to_bytes(x_int, nbytes)

# Remove padding (PKCS#7 padding)
padding_len = flag_bytes[-1]
flag = flag_bytes[:-padding_len]

print("Recovered flag:", flag.decode())