# Load the Coppersmith implementation
load('coppersmith.sage')

# Given values
n = 147170819334030469053514652921356515888015711942553338463409772437981228515273287953989706666936875524451626901247038180594875568558137526484665015890594045767912340169965961750130156341999306808017498374501001042628249176543370525803456692022546235595791111819909503496986338431136130272043196908119165239297

# Compute b (from previous steps)
r_mod = (1 << 256) - (n % (1 << 256))
p_bits = []
for i in range(128, 256):
    pos = 511 - 2 * i
    bit = (r_mod >> pos) & 1
    p_bits.append(bit)
b = sum(bit * (1 << j) for j, bit in enumerate(p_bits[::-1]))

# Define the polynomial ring and polynomial
R = Integers(n)
P.<a> = PolynomialRing(R)
f = a * (1 << 384) + b * (1 << 256) + ((1 << 256) - 1)

# Set bounds (a < 2^128)
bounds = (2^128,)

# Apply Coppersmith's method
roots = small_roots(f, bounds, m=2)
print("Roots:", roots)

# Recover p, q, r
for a in roots:
    p = a * (1 << 128) + b
    q = p * (1 << 256) + ((1 << 256) - 1)
    if n % q == 0:
        r = n // q
        print(f"p = {p}")
        print(f"q = {q}")
        print(f"r = {r}")
        break