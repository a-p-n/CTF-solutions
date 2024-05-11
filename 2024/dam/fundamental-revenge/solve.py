from pwn import *
from Crypto.Util.number import *
io = remote('chals.damctf.xyz',31414)

p = 168344944319507532329116333970287616503
def pad(m):
    padlen = 16 - (len(m) % 16)
    padding = bytes([padlen] * padlen)
    return m + padding

def to_coeffs(m):
    coeffs = []
    for i in range(0, len(m), 16):
        chunk = m[i:i+16]
        coeffs.append(int.from_bytes(chunk,'big'))

    return coeffs

def poly_eval(coeffs, x):
    res = 0
    for c in coeffs:
        res = (c + x * res) % p
    return res

def auth(s, k, m):
    coeffs = to_coeffs(m)
    mac_int = (poly_eval(coeffs, k) + s) % p
    return mac_int.to_bytes(16,'big')


msg = b'gonna ace my crypto final with a' + b'a'*16
target = b"gonna ace my crypto final with all this studying"
nil = b'\x00'*16
# a*x + a + s mod p
print(to_coeffs(target))
coeff_a = 168344944319507532329116333970287616503
coeff_need = 153387921715870300241881447980350140524
io.recvuntil(b'message to sign (hex): ')
io.sendline(msg.hex().encode())
io.recvuntil(b'authentication tag: ')
auth_tag = bytes_to_long(bytes.fromhex(io.recvline().strip().decode()))

# print(hex(auth_tag))
# s_guess = auth_tag%coeff
# x_guess = (((auth_tag - coeff - s_guess)%p) * pow(coeff,-1,p))%p

io.recvuntil(b"enter verification tag (hex): ")
# print(auth(s_guess,x_guess,msg).hex())
io.sendline(long_to_bytes((auth_tag - coeff_a + coeff_need)%p).hex().encode())
io.interactive()