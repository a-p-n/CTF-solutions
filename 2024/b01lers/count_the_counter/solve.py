from pwn import *
from binascii import unhexlify, hexlify

# context.log_level = 'debug'
r = remote('gold.b01le.rs', 5002)

r.recvline()
encrypted_flag_hex = r.recvline().strip()
encrypted_flag = unhexlify(encrypted_flag_hex)
print(len(encrypted_flag))

for i in range(600):
    print(i)
    r.sendline(hexlify(encrypted_flag))

lines = r.recvall()
lines = lines.split(b'\n')
for line in lines:
    try:
        dat = line.split(b': ')[-1]
        dat = unhexlify(dat)
        if b'bctf{' in dat:
            print(dat)
            break
    except:
        pass