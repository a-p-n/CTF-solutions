from pwn import *

p = 0x5F1586368F278CAAFF7289F5D6E24FD229F6E1CCB86C52B5779AC853552BE79
a = 0x1337
b = 0x2A5B8AC6AA0565DEF105AE1788FC56EB75C9891062883F34A2C8DAD628C4F87
q = 0x5F1586368F278CAAFF7289F5D6E24FD20D6D6C59C6B6ACFE4272E85E7E98319
G = (
    0x4C146983EE247BCC1174004BF95282BC97BDDE453C82405B18D53E84564B250,
    0x279F15F24D01328F1488E089FC987BA0643715D6BBBC89646FBD6A3DC95B4AA,
    0x1,
)

HOST = "outer_wilds.tasks.ctf.ad"
PORT = 1188

def inv(x): return pow(x, p-2, p)

def to_affine(P):
    X, Y, Z = P
    if Z % p == 0:
        return (0, 0)
    z2 = (Z*Z) % p
    z3 = (z2*Z) % p
    return ((X*inv(z2)) % p, (Y*inv(z3)) % p)

def ecc_neg(P): X,Y,Z=P; return (X, (-Y)%p, Z)

def ecc_add(P,Q):
    X0,Y0,Z0 = P; X1,Y1,Z1 = Q
    U0 = (X0*pow(Z1,2,p))%p; S0=(Y0*pow(Z1,3,p))%p
    U1 = (X1*pow(Z0,2,p))%p; S1=(Y1*pow(Z0,3,p))%p
    W=(U0-U1)%p; R=(S0-S1)%p; T=(U0+U1)%p; M=(S0+S1)%p
    Z2=(W*Z0*Z1)%p
    X2=(R*R - T*(W*W%p))%p
    V=(T*(W*W%p)-2*X2)%p
    half=(p+1)>>1
    Y2=(half*( (V*R - M*(W*W%p)*W)%p ))%p
    return (X2,Y2,Z2)

def ecc_sub(P,Q): return ecc_add(P,ecc_neg(Q))

def predict_parity(R):
    X, Y, Z = R

    # A point with Z=0 is the point at infinity. This implies the scalar k
    # is a multiple of the group order. For this challenge, this is impossible,
    # but as a fallback, k=0 is even.
    if Z == 0:
        return 0

    # Step 1: Convert from Jacobian to Affine to get the x-coordinate.
    # The formula is x = X / Z^2 (mod p). We use modular inverse for division.
    # z_inv_sq = pow(Z*Z, p-2, p)
    # x = (X * z_inv_sq) % p
    # A more efficient way to write it:
    z_inv = pow(Z, p - 2, p)
    x = (X * pow(z_inv, 2, p)) % p

    # Step 2: Calculate the Legendre Symbol of x.
    # The formula is L = x^((p-1)/2) (mod p).
    legendre_symbol = pow(x, (p - 1) // 2, p)

    # Step 3: Map the symbol to the parity.
    # We verified with the generator G that for k=1 (odd), L=1.
    # This confirms the following mapping is correct for this curve.
    if legendre_symbol == 1:
        # L=1 means x is a quadratic residue, which means k is ODD.
        return 1
    elif legendre_symbol == p - 1:
        # L=p-1 (or -1) means x is a quadratic non-residue, which means k is EVEN.
        return 0
    else:
        # L=0 is not expected. Default to a guess.
        return 0
# ----- main -----
def solve():
    conn = remote(HOST, PORT)
    conn.recvuntil(b"win BIG\n\n")

    for i in range(1,1001):
        conn.recvuntil(b"R = ")
        r_str = conn.recvline().strip().decode()
        R = eval(r_str)
        bit = predict_parity(R)
        conn.sendlineafter(b"?????? > ", str(bit).encode())
        log.info(f"Round {i}: predicted {bit}")

    conn.interactive()

if __name__ == "__main__":
    solve()
