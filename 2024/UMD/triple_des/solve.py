from pwn import *
from tqdm import trange

io = remote('challs.umdctf.io', 32333)
io.recvuntil(b"Here's the encrypted flag: ")
enc_flag = bytes.fromhex(io.recvline().strip().decode())
flag_blocks = [enc_flag[i:i+8] for i in range(0, len(enc_flag), 8)]
assert len(flag_blocks) == 9
iv1, eiv2, eiv3, b1, b2, b3, b4, b5 = [flag_blocks[i] for i in range(8)]

def oracle(iv1, eiv2, eiv3, block):
    decrypted = []
    for i in range(1, 9):
        if i == 1:
            for j in trange(256):
                payload = iv1[:8-i] + bytes([j]) + eiv2 + eiv3 + block
                assert len(payload) % 8 == 0 and len(payload) == 32
                io.recvuntil(b"Give us an encrypted text and we'll tell you if it's valid!\n")
                io.sendline(payload.hex().encode())
                res = io.recvline().strip().decode()
                if res == "yes":
                    decrypted.append(j ^ iv1[8-i] ^ i)
                    print("Found:", bytes(decrypted[::-1]))
                    break

        else:
            for j in trange(256):
                payload = iv1[:8-i] + bytes([j]) + bytes([iv1[8-(len(decrypted)-cnt)] ^ x ^ i for cnt, x in enumerate(decrypted[::-1])]) + eiv2 + eiv3 + block
                assert len(payload) % 8 == 0 and len(payload) == 32
                io.recvuntil(b"Give us an encrypted text and we'll tell you if it's valid!\n")
                io.sendline(payload.hex().encode())
                res = io.recvline().strip().decode()
                if res == "yes":
                    decrypted.append(j ^ iv1[8-i] ^ i)
                    print("Found:", bytes(decrypted[::-1]).decode())
                    break
    print(bytes(decrypted[::-1]).decode())


oracle(b2, b3, b4, b5)
io.interactive()
# UMDCTF{padding_oracle_with_extra_steps?}
