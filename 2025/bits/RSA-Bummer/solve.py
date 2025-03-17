#!/usr/bin/env python3
from pwn import remote, context, log
from math import gcd
from Crypto.Util.number import long_to_bytes, inverse
from gmpy2 import iroot

context.log_level = "debug"

def rsa_decrypt_modp(c, e, p):
    g = gcd(e, p - 1)
    if g == 1:
        d = inverse(e, p - 1)
        return pow(c, d, p)
    else:
        e_prime = e // g
        t = (p - 1) // g
        d_prime = inverse(e_prime, t)
        X = pow(c, d_prime, p)
        log.info("Computed X = m^g mod p: {}".format(X))
        root, exact = iroot(X, g)
        if exact:
            log.info("Successfully extracted integer g-th root using gmpy2")
          
            return int(root)
        else:
            raise Exception("No valid g-th root found")

def recv_until_keyword(r, keyword):

    while True:
        line = r.recvline().decode().strip()
        log.debug("Received: " + line)
        if keyword in line:
            return line

def get_lucky_output(r, x):

    
    r.recvuntil("Enter your lucky number : ")
    r.sendline(str(x))
    line = r.recvline().decode().strip()
    if "Your lucky output" not in line:
        line = r.recvline().decode().strip()
    val = int(line.split(':')[-1].strip())
    r.recvline()
    return val

def main():
    HOST = "chals.bitskrieg.in"
    PORT = 7001

    r = remote(HOST, PORT)
    

    line = recv_until_keyword(r, "Pseudo_n")
    pseudo_n = int(line.split('=')[-1].strip())
    log.info("Parsed Pseudo_n = {}".format(pseudo_n))
    

    line = recv_until_keyword(r, "e =")
    e = int(line.split('=')[-1].strip())
    log.info("Parsed e = {}".format(e))
    

    cts = []
    for i in range(3):
        line = recv_until_keyword(r, "Ciphertext")
        ct = int(line.split('=')[-1].strip())
        cts.append(ct)
        log.info("Parsed Ciphertext {}: {}".format(i+1, ct))
    F3 = get_lucky_output(r, 3)
    log.info("F(3) = {}".format(F3))
    F4 = get_lucky_output(r, 4)
    log.info("F(4) = {}".format(F4))
    
    n_val = F3 + 4 * F4
    log.info("Recovered n (p * r) = {}".format(n_val))

    r_val = gcd(n_val, pseudo_n)
    log.info("Recovered r = {}".format(r_val))
    p_val = n_val // r_val
    log.info("Recovered p = {}".format(p_val))

    flag_parts = []
    for idx, ct in enumerate(cts, start=1):
        m_int = rsa_decrypt_modp(ct, e, p_val)
        part = long_to_bytes(m_int)
        log.info("Decrypted part {}: {}".format(idx, part))
        flag_parts.append(part)
    
    flag = b"".join(flag_parts)
    log.success("Flag: {}".format(flag.decode()))
    r.close()

if __name__ == "__main__":
    main()
