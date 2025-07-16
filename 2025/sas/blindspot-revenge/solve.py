from pwn import *
import hashlib
import json
from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import Point
import secrets

context.log_level = 'debug'

HOST, PORT = "tcp.sasc.tf", 12447

curve = NIST256p
G = curve.generator
p = int(G.order())

def point2bytes(P):
    return P.to_bytes()

def hash_func(Rp, m):
    if isinstance(m, str):
        m = m.encode()
    return int.from_bytes(hashlib.sha256(point2bytes(Rp) + m).digest(), 'big') % p

def forge_blind_signature(io, msg):
    io.recvline()
    io.send(b"sign")
    data = json.loads(io.recvline())
    R = Point(curve.curve, *data["R"])
    Q = Point(curve.curve, *data["Q"])

    alpha = secrets.randbelow(p)
    beta = secrets.randbelow(p)
    while alpha == 0 or beta == 0:
        alpha = secrets.randbelow(p)
        beta = secrets.randbelow(p)

    R_blind = R + G * alpha + Q * beta
    c_prime = hash_func(R_blind, msg)
    c = (c_prime + beta) % p

    io.sendline(json.dumps({"c": int(c)}).encode())
    s = int(json.loads(io.recvline())["s"])
    s_prime = int((s + alpha) % p)

    R_aff = R_blind.to_affine()
    x = int(R_aff.x()) % p
    y = int(R_aff.y()) % p
    sig = [[x, y], s_prime]

    return sig

def verify_signature(msg, sig):
    io = remote(HOST, PORT)
    io.recvline()
    io.send(b"verify")
    io.sendline(json.dumps({"msg": msg, "sig": sig}).encode())
    try:
        resp = io.recvuntil(b"}\n", timeout=2)
        print("[+] Server response:", resp.decode())
    except EOFError:
        print("[-] Server closed connection unexpectedly.")
    io.close()

io = remote(HOST, PORT)
sig1 = forge_blind_signature(io, "get_flag")
io.close()

io = remote(HOST, PORT)
sig2 = forge_blind_signature(io, "message1")
io.close()

verify_signature("get_flag", sig1)
verify_signature("message1", sig2)