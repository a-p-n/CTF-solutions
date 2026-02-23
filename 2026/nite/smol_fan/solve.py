from sage.all import *
from pwn import *
import hashlib
from ecdsa.curves import SECP256k1

HOST = 'smol.chals.nitectf25.live'
PORT = 1337
context.log_level = 'info'

curve = SECP256k1
order = int(curve.order)
G = curve.generator

def get_r_s(m, a):
    val = a - pow(10, 11)
    r = gcd(val, m)
    s = m // r
    return int(r), int(s)

def solve():
    io = remote(HOST, PORT, ssl=True)
    
    io.sendlineafter(b'> ', b'1')
    io.recvuntil(b'Qx = ')
    Qx = int(io.recvline().strip())
    io.recvuntil(b'Qy = ')
    Qy = int(io.recvline().strip())
    print(f"[+] Public Key: ({Qx}, {Qy})")

    sigs = []
    print("[+] Sig farming")
    
    for i in range(8):
        msg_str = f"burn_the_fans_{i}"
        msg_bytes = msg_str.encode()
        msg_hash = int(hashlib.sha256(msg_bytes).hexdigest(), 16)
        
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b'hex: ', msg_bytes.hex().encode())
        
        io.recvuntil(b'm = ')
        m_val = int(io.recvline().strip())
        io.recvuntil(b'a = ')
        a_val = int(io.recvline().strip())
        io.recvuntil(b'b = ')
        _ = io.recvline() 
        
        r, s = get_r_s(m_val, a_val)
        
        # Filter invalid points
        if r > 1 and s > 1:
            sigs.append({'r': r, 's': s, 'z': msg_hash})
            print(f"    [{i+1}] Recovered (r, s)")
        else:
            print(f"    [{i+1}] Failed to recover r, s (skipping)")

    print("[*] Constructing lattice...")
    m = len(sigs)
    M = Matrix(ZZ, m + 2, m + 2)
    
    for i in range(m):
        M[i, i] = order * 2**56

    for i in range(m):
        r, s, z = sigs[i]['r'], sigs[i]['s'], sigs[i]['z']
        
        s_inv = inverse_mod(s, order)
        t = (r * s_inv) % order
        u = (z * s_inv) % order
        
        M[m, i] = t * 2**56
        M[m+1, i] = u * 2**56
        
    M[m, m] = 1
    M[m + 1, m + 1] = order

    print("[*] Running LLL (this might take a second)...")
    L = M.LLL()
    
    d_found = 0
    
    for row in L:
        potential_d = abs(int(row[m]))
        if potential_d == 0: continue
        
        try:
            Pub = potential_d * G
            if Pub.x() == Qx and Pub.y() == Qy:
                d_found = potential_d
                print(f"[+] FOUND PRIVATE KEY d: {d_found}")
                break
        except:
            continue
            
    if d_found == 0:
        print("[-] Failed. Lattice reduction didn't find d. Try again.")
        return

    # 4. Claim Flag
    print("[*] Signing flag message...")
    from ecdsa import SigningKey
    sk = SigningKey.from_secret_exponent(d_found, curve=SECP256k1)
    sig = sk.sign(b"gimme_flag", hashfunc=hashlib.sha256)
    
    r_final = int.from_bytes(sig[:32], 'big')
    s_final = int.from_bytes(sig[32:], 'big')
    
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'r: ', str(r_final).encode())
    io.sendlineafter(b's: ', str(s_final).encode())
    
    print(io.recvall().decode())

if __name__ == "__main__":
    solve()