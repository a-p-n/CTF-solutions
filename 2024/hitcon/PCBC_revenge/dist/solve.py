import binascii
from pwn import *
from functools import reduce

HOST = 'pcbcrevenge.chal.hitconctf.com'
PORT = 3000

def get_valid_certificate():
    r.recvuntil(b"Here is a valid certificate: ")
    return r.recvline().strip().decode()

def verify_certificate(cert):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Give me a certificate >> ", cert.encode())
    response = r.recvline().strip().decode()
    return "valid" in response

def xor(*args):
    _xor = lambda x1, x2: x1^x2
    return bytes(map(lambda x: reduce(_xor, x, 0), zip(*args)))

def decrypt_block(known_block, cipher_block, prev_cipher_block):
    result = bytearray(16)
    for i in range(15, -1, -1):
        for byte in range(256):
            test_block = bytearray(16)
            test_block[i] = byte
            for j in range(i + 1, 16):
                test_block[j] = result[j] ^ (16 - i)
            
            modified_prev = xor(prev_cipher_block, xor(test_block, known_block))
            test_cert = modified_prev.hex() + cipher_block.hex()
            if verify_certificate(test_cert):
                result[i] = byte ^ (16 - i)
                break
        if i == 0:
            break
    
    return xor(result, known_block)

def solve_challenge():
    valid_cert = get_valid_certificate()
    cert_bytes = binascii.unhexlify(valid_cert)
    
    iv = cert_bytes[:16]
    blocks = [cert_bytes[i:i+16] solve_challengefor i in range(16, len(cert_bytes), 16)]
    
    known_block = b'\x00' * 16
    decrypted = b''
    
    for i in range(len(blocks) - 1, -1, -1):
        if i == 0:
            prev_block = iv
        else:
            prev_block = blocks[i-1]
        
        dec_block = decrypt_block(known_block, blocks[i], prev_block)
        decrypted = dec_block + decrypted
        known_block = dec_block
    
    return decrypted

r = remote(HOST, PORT)
flag = solve_challenge()

print("Decrypted flag:", flag)
r.close()