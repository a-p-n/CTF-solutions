from Crypto.Util.number import long_to_bytes
from base64 import b64decode
from pwn import xor

ct = b64decode(b"LEs2fVVxNDMfNHEtcx80cB8nczQfJhVkDHI/Ew==")

flag_len = len(ct)

flag = list(b"flag{" + b"0"*(flag_len-6) + b"}")
key = list(b"0" * 7)

key[0] = xor(ct[0], flag[0])
key[1] = xor(xor(ct[1], flag[1]), key[0])
key[2] = xor(xor(xor(ct[2], flag[2]), key[1]), key[0])
key[3] = xor(xor(xor(xor(ct[3], flag[3]), key[2]), key[1]), key[0])
key[4] = xor(xor(xor(xor(xor(ct[4], flag[4]), key[3]), key[2]), key[1]), key[0])

pt = list(ct)
for k in range(257,256**2):
    pt1 = list(ct)
    key[5] = chr(long_to_bytes(k)[0]).encode()
    key[6] = chr(long_to_bytes(k)[1]).encode()
    print(key)
    for i in range(0, len(ct) - len(key) + 1):
        for j in range(0, len(key)):
            pt1[i+j] = xor(pt1[i+j], key[j])
    if pt1[-1] == ord("}"):
        print(b''.join(pt1))
