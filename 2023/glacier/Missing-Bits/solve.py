from Crypto.PublicKey import RSA

with open("/home/apn/Documents/bi0s/my_git/Crypto/ctf/glacier/Missing-Bits/priv.key", "r") as f:
    key = RSA.importKey(f.read())

with open("/home/apn/Documents/bi0s/my_git/Crypto/ctf/glacier/Missing-Bits/ciphertext_message", "rb") as f:
    ct = f.read()

n = key.n
e = key.e

print(n,e,ct)