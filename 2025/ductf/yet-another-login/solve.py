from pwn import *
from hashlib import sha256
from Crypto.Util.number import bytes_to_long, long_to_bytes

HOST = 'chal.2025.ductf.net' 
PORT = 30010
log.level = 'debug'

def solve():
    conn = remote(HOST, PORT)

    n_str = conn.recvline().strip().decode()
    n = int(n_str)
    n2 = n * n
    g = n + 1
    log.info(f"Received n = {n}")

    # 2. Register a non-admin user to get a valid token
    conn.sendlineafter(b'> ', b'1')
    username = b'guest'
    conn.sendlineafter(b'Username: ', username)
    
    # 3. Receive the token and parse it
    conn.recvuntil(b'Token: ')
    token_hex = conn.recvline().strip().decode()
    token = bytes.fromhex(token_hex)
    msg_guest, _, mac_guest_bytes = token.partition(b'|')
    c_guest = bytes_to_long(mac_guest_bytes)
    log.success(f"Got token for '{username.decode()}'")

    # 4. Calculate the hashes for guest and admin messages (without the secret)
    h_guest_nosk = bytes_to_long(sha256(b'user=guest').digest())
    h_admin_nosk = bytes_to_long(sha256(b'user=admin').digest())
    
    # 5. Calculate the delta needed to transform the guest hash to the admin hash
    # We need delta = (h_admin - h_guest) mod 2^256
    delta = (h_admin_nosk - h_guest_nosk) % (2**256)
    log.info("Calculated delta")

    # 6. Encrypt delta using the Paillier scheme (with r=1)
    # E(delta) = g^delta mod n^2
    c_delta = pow(g, delta, n2)
    log.info("Calculated ciphertext for delta")

    # 7. Forge the admin MAC using the homomorphic property
    # c_admin = c_guest * c_delta mod n^2
    c_admin = (c_guest * c_delta) % n2
    mac_admin_bytes = long_to_bytes(c_admin)
    log.success("Forged admin MAC")

    # 8. Create the final admin token
    msg_admin = b'user=admin'
    admin_token = msg_admin + b'|' + mac_admin_bytes
    
    # 9. Login as admin
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'Token: ', admin_token.hex().encode())

    # Receive and print the flag
    conn.recvuntil(b'Welcome b\'admin\'!\n')
    flag = conn.recvline().strip().decode()
    log.success(f"FLAG: {flag}")
    
    conn.close()


if __name__ == '__main__':
    solve()