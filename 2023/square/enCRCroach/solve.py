import fastcrc
import requests
from pwn import xor

def gen_mac(data: bytes) -> bytes:
    # A 64-bit CRC should be pretty good. Faster than a hash, and can't be brute forced.
    crc = fastcrc.crc64.go_iso(data)
    return int.to_bytes(crc, length=8, byteorder="big")

token = bytes.fromhex(requests.get("http://184.72.87.9:8002/auth?user=azure&password=hunter2").text)

payload = xor(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*50, token)

a = gen_mac(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*42)
b = gen_mac(b'\x00'*63)
mac = xor(a, b)

payload = xor(payload, b'\x00'*63 + mac)

print(requests.get("http://184.72.87.9:8002/read/flag.txt?token="+payload.hex()).text)
# flag{r0llin_my_0wn_crypt0_311c4f2a}
