# TAFT function
# some ^ good = T[0]
# some ^ sha1(good) = T[1]
# some ^ sha1(sha1(good)) = T[2]
# some ^ sha1(sha1(sha1(good))) = T[3]
# T[0] ^ T[1] = good ^ sha1(good)

# GAZ function
# 
import multiprocessing
import ast
from Crypto.Cipher import AES
from hashlib import *
from Crypto.Util.number import *

def next_prime(n):
	while True:
		if isPrime(n):
			return n
		n += 1

def decrypt(enc, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    dec = cipher.decrypt_and_verify(enc, tag)
    return dec

def xor(mm, ym):
	xm = []
	for i in range(len(mm)):
		xm.append(mm[i] ^ ym[i])
	return bytes(xm)

with open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/asis-finals/M7P/output.txt","r") as f1:
    a = f1.readlines()

G = ast.literal_eval(a[0][4:-1])
L = ast.literal_eval(a[1][4:-1])
enc = b"\x8d\x04>\xeb4S\xf3\xea\x9c\xc1\xec3\x07\xfc'\xf9\xd7\xfcQ\\\xcf&\xc6N\xa1\xf1\xa4\x87\xee\xf6\xe3\x0c\xfbF,yyq\xfdK\x95\x94\x152\x9c\xcbK\x97\n\xe2#"
cipher_nonce = b'B\xe3@\xee\x1ex\xee\xca \x14\x1bPT\xee\x92\x9c'
tag = b'\xeb\xacdC\x85=\x17^}\x80/N\xcc\xc4F\xa3'

def reverse_lili(G, L):
    keys = b''
    for g, l in zip(G, L):
        for i in range(2**16):
            s_i = bin(i)[2:].zfill(16)
            if sum([g[_] * int(s_i[_]) for _ in range(16)]) == l:
                keys += long_to_bytes(i)
                break
    return keys
# keys = reverse_lili(G, L)
keys = b'N\x9d\xf8{\n-9)\x84\xaa\xa1z\x80\xb2\x0fE\x17=5\x8e|h\xd6\x1f\x88\xb0\xaea\x07h\xaf\x954\x17t^\x84\xbe\xa8\xecM\r\x98\x1d\xfe\x1d\x04\xda\xbc\xcd.n\xbe\x96N\xa0i@Qh"\x07\xdb\xf50\x84\x83\xb3\x99\xb9P\xdb\xae\xff+\xfff>\xdfJ'
# print(keys)


def reverse_gaz_worker(args):
    G, idx = args
    i = G[idx]
    p = max(i)
    if not isPrime(p):
        p = next_prime(p)
    a = next_prime(2 ** ((p.bit_length() >> 3) - 1))
    while True:
        r = [(j * inverse(a, p)) % p for j in i]
        if p == next_prime(sum(r)):
            return idx, r
        a = next_prime(a + 1)


def reverse_gaz(G):
    R = []
    pool = multiprocessing.Pool()

    # Prepare the arguments for parallel processing
    worker_args = [(G, idx) for idx in range(len(G))]

    # Use multiprocessing to parallelize the computation
    results = pool.map(reverse_gaz_worker, worker_args)

    # Collect the results
    for idx, r in results:
        R.append(r)
        print(r)

    return R


print(reverse_gaz(G))

mask = decrypt(enc, cipher_nonce, tag, some)
flag = xor(mask, sha512(keys).digest()[:len(mask)])