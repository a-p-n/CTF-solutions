from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Util.number import isPrime

with open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/tamu/truncated-2/public.pem", "r") as f:
    public_key = RSA.importKey(f.read())
    n = public_key.n
    e = public_key.e

print(n, e)

with open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/tamu/truncated-2/private.pem", "r") as f:
    private_key = f.read().split("---")[0].encode()

private_key = b64decode(private_key).hex()
print(private_key)

l = private_key.split("028180")
dp = 0x4894e9fa2c26b0e1c631ced2f86be0207a82751d707b018839565e93f551df596e9d16f05599a2bfb0bbb300064139f383de85c793e058da2cce41a9a0398e40be05bb9b82703fe804164f5ff4d76623d0e4c720fd705ce6eface979489a8b3a2bd6630077699c0aa8da6250c1de8840d3e5afc34db865e0650ce08f828b49ad02
dq = 0x54d4d1981870d799334e5ae5174526d2979e14c6ecc74d7b59600fbf7db4c060481c3d38c83aa4048e4c6ad483a416d43aecc58db7fe8b9e3d114187538c02b22c9197fe3afd23a83f6e9ac33fab55c84776b1de23a6057e91c47e36ab2ac7600adbbfeb4159d8b09d81898f9a04e47b679cbe690daf6a60551f2b822786337702
print(f"dp: {dp}\ndq: {dq}")
for kp in range(1, e):
    p_mul = dp * e - 1
    if p_mul % kp == 0:
        p = (p_mul // kp) + 1
        if n%p == 0:
            print(f"Possible p: {p}")
