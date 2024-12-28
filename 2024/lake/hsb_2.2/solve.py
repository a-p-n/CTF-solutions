from  pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, GCD
from secrets import choice

RSA_LEN = 256

def get_random_bytes(l: int):
    alph = list(range(1, 256))
    return b"".join([bytes([choice(alph)]) for _ in range(l)])

def pad(p: bytes) -> bytes:
    return get_random_bytes(RSA_LEN - len(p) - 2) + b"\x00" + p

io = remote('chall.polygl0ts.ch', 9067)
io.recvuntil(b"Enter selected option: ")
io.sendline(b"2")
io.recvuntil(b"Enter selected option: ")
io.sendline(b"6")
io.recvline()
export_secret = int(io.recvline().decode().strip()[12:])

m_list = [bytes_to_long(b"1"*253), bytes_to_long(b"2"*253), bytes_to_long(b"3"*253), bytes_to_long(b"4"*253), bytes_to_long(b"5"*253), bytes_to_long(b"6"*253)]
m_pow_list = [pow(m_list[i],65537) for i in range(6)]
mod_list = []

for i in range(6):
    io.recvuntil(b"Enter selected option: ")
    io.sendline(b"4")
    io.recvuntil(b"input 0: ")
    print("Ok")
    io.sendline(f"{m_list[i]}".encode())
    mod_list.append(int(io.recvline().decode().strip()[12:]) - m_pow_list[i])
_GCD = mod_list[0]
for i in range(6):
    _GCD = GCD(_GCD, mod_list[i])
N = _GCD
print(N)
io.close()
