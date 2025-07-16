from pwn import *
import hashlib
import json
from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import Point
import secrets

context.log_level = 'debug'

HOST, PORT = "tcp.sasc.tf", 14008

curve = NIST256p
G = curve.generator
p = G.order()

def point2bytes(P):
    return P.to_bytes()

def hash_func(Rp, m):
    if isinstance(m, str):
        m = m.encode()
    return int.from_bytes(hashlib.sha256(point2bytes(Rp) + m).digest(), 'big') % p

def verify(msg, sig):
    io = remote(HOST, PORT)
    io.sendline(json.dumps({"cmd": "VERIFY", "msg": msg, "sig": sig}).encode())
    resp = io.recvline()
    io.close()
    return resp.decode().strip()

io = remote(HOST, PORT)

io.sendline(json.dumps({'cmd': 'REQUEST'}).encode())
resp = io.recvline()
data = json.loads(resp)
R = Point(curve.curve, *data['R'])
Q = Point(curve.curve, *data['Q'])

c1 = secrets.randbelow(p)
c2 = secrets.randbelow(p)
while c1 == c2:
    c2 = secrets.randbelow(p)

io.sendline(json.dumps({"cmd": "CHALLENGE", "c": str(c1)}).encode())
s1 = int(json.loads(io.recvline())["s"])

io.sendline(json.dumps({"cmd": "CHALLENGE", "c": str(c2)}).encode())
s2 = int(json.loads(io.recvline())["s"])

diff_s = (s1 - s2) % p
diff_c = (c1 - c2) % p
inv_diff_c = pow(diff_c, -1, p)
d = (diff_s * inv_diff_c) % p
k = (s1 - c1 * d) % p

log.success(f"Recovered private key d: {d}")
log.success(f"Recovered nonce k: {k}")

messages = ["get_flag", "message1", "message2"]

for msg in messages:
    c = hash_func(R, msg)
    s = (k + c * d) % p
    signature = ((int(R.x()), int(R.y())), int(s))
    
    result = verify(msg, signature)
    log.info(f"Verified message '{msg}': {result}")

final_msg = "get_flag"
final_c = hash_func(R, final_msg)
final_s = (k + final_c * d) % p
final_signature = ((int(R.x()), int(R.y())), int(final_s))

final_result = verify(final_msg, final_signature)
print("\nServer response:\n" + final_result)

if "here is your prize" in final_result:
    log.success("Flag captured!")
else:
    log.error("Exploit failed.")
