from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import unpad
from hashlib import sha256
import json
from sympy.ntheory.modular import crt

context.log_level = "debug"

def decrypt_flag(key, encrypted_data):
    key = sha256(str(key).encode()).digest()
    iv = bytes.fromhex(encrypted_data['iv'])
    ct = bytes.fromhex(encrypted_data['enc_flag'])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), 16)

    return pt

url = "94.237.52.253"
port = 51816
primes = [getPrime(15) for i in range(19)]
ans = []

r = remote(url, port)
r.recv()
data = {"command" : "get_share", "x" : "7"}
for i in range(19):
    data["x"] = str(primes[i])
    r.sendline(json.dumps(data))
    result = json.loads(r.recvline())
    ans.append(result["y"] % primes[i])
    r.recv()

data = {"command" : "encrypt_flag"}
r.sendline(json.dumps(data))
r.recvuntil(":")
flag = r.recvline().decode()[:-2]
flag = json.loads(flag)
print(flag)

key = crt(primes, ans)[0]
print(decrypt_flag(key, flag))
# https://hiumee.com/posts/HTB-University-CTF-MSS/