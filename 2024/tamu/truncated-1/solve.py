from sympy import *
from Crypto.Util.number import bytes_to_long, isPrime
import base64
from Crypto.PublicKey import RSA
import re

with open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/tamu/truncated-1/public.pem", "r") as f:
    public_key = RSA.importKey(f.read())
    n = public_key.n
    e = public_key.e

print(n, e)

with open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/tamu/truncated-1/private.pem", "r") as f:
    private_key = f.read().split("---")[0].encode()
private_key = base64.b64decode(private_key).hex()

delimiters = ["010001", "02820100", "02818100"]

pattern = f"({'|'.join(map(re.escape, delimiters))})"
result = re.split(pattern, private_key)

result = [sub for sub in result if sub not in delimiters and sub != ""]

d = int(result[0], 16)
dq = int(result[1], 16)
dp = int(result[2], 16)

print(f"dp: {dp}\ndq: {dq}")

N = 10000000
M = 1

for j in range(N, 1, -1):
	q_ = (e * dq - 1)//j + 1
	if str(hex(d)[2:]) in str(hex(q_)):
		print(q_, j)

for kp in range(3, e):
    p_mul = dp * e - 1
    if p_mul % kp == 0:
        p = (p_mul // kp) + 1
        if isPrime(p):
            print(f"Possible p: {p}")
