from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from sage.all import *
from icecream import ic

P = 2
N = 150
def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)

KEY_LENGTH = 128
def derive_aes_key(M):
    mat_str = ''.join(str(x) for row in M for x in row)
    return SHA256.new(data=mat_str.encode()).digest()[:KEY_LENGTH]


G = load_matrix("/home/apn/Documents/bi0s/my_git/bi0s/ctf/mapna/glnq/generator.txt")
A_pub = load_matrix("/home/apn/Documents/bi0s/my_git/bi0s/ctf/mapna/glnq/alice.pub")
B_pub = load_matrix("/home/apn/Documents/bi0s/my_git/bi0s/ctf/mapna/glnq/bob.pub")

if G.is_invertible():
    m = ic(discrete_log(B_pub, G,algorithm='lambda'))
    assert B_pub==G^m, 'not-yet'
    print(f"m= {m}")
else:
    print('no')

shared_secret = A_pub^m

key = derive_aes_key(shared_secret)
iv = bytes.fromhex('43f14157442d75142d0d4993e99a9582')
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = bytes.fromhex('22abc3b347ffef55ec82488e5b4a338da5af7ef1918ac46f95029a4d94ace4cb2700fa9aeb31e6a4facee2601e99dabd6f9a81494c55f011e9227c9a6ae8d802')
print(cipher.decrypt(ciphertext))