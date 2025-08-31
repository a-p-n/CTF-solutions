from sage.all import *

K2 = GF(2)["x"]
modulus_pol = sage_eval("x^128 + x^7 + x^2 + x + 1", locals={"x": K2.gen()})
F = GF(2).extension(modulus_pol, name="x")

def to_field(b: bytes):
    return F.from_integer(int.from_bytes(b, "big"))

def from_field(f):
    return f.to_integer().to_bytes(16, "big")

def xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b1, b2))

ct_24 = bytes.fromhex("9019C5F8C5DB894F4FDAA07B57A4D782769A58CA0DC1BC81A49ABD10689ED91B")
ct_24_1, ct_24_2 = ct_24[:16], ct_24[16:]
nonce_24 = bytes.fromhex("6B6173706572736B797B6E33775F6230")
winner_id = bytes.fromhex("7B000F6DCE23C1F9842F219E35F9E388")
pt_24 = b"CTF2024 winner: " + winner_id
pt_24_1, pt_24_2 = pt_24[:16], pt_24[16:]

ct2 = bytes.fromhex("25D4FF5A815E487E8CA07BDDF3FC697700000000000000000000000000000000")
ct2_1 = ct2[:16]
pt2 = bytes.fromhex("3E11257338119254228180CFA70F5EFB930AC3D57EEBC599BB2BA4BF4778C325")
pt2_1, pt2_2 = pt2[:16], pt2[16:]

p2025_1 = b"CTF2025 winner: "

h24_1 = xor(pt_24_1, ct_24_1)
hp_1 = xor(pt2_1, ct2_1)
gamma24_2 = xor(pt_24_2, ct_24_2)

tau_p_val = to_field(ct2_1) * to_field(hp_1)
h24_2 = from_field(tau_p_val * to_field(ct_24_2)**-1)

print(f"[+] Successfully calculated secret H_24_2: {h24_2.hex()}")

f_h24_1 = to_field(h24_1)
f_c24_1 = to_field(ct_24_1)
f_p2025_1 = to_field(p2025_1)
f_c24_2 = to_field(ct_24_2)
f_h24_2 = to_field(h24_2)
f_gamma24_2 = to_field(gamma24_2)

A = (f_c24_1 + f_p2025_1 + f_h24_1) * f_h24_1 + f_c24_2 * f_h24_2
W_plus_gamma = A * f_h24_2**-1
f_W = W_plus_gamma + f_gamma24_2

winner_id_2025 = from_field(f_W)

flag_nonce = nonce_24
flag = flag_nonce + winner_id_2025

print(f"[+] Calculated winner_id_2025: {winner_id_2025.hex()}")
print(f"\n[+] Forgery successful!")
print(f"  - Chosen Nonce: {flag_nonce.hex()}")
print(f"  - Derived Winner ID: {winner_id_2025.hex()}")
print(f"\n🏁 Flag: {flag.decode()}")