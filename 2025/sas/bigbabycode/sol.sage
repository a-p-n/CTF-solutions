import numpy as np
from Crypto.Util.number import long_to_bytes

F = GF(2)

G_pub = np.load('alice_pub.npy')
G = matrix(F, G_pub.tolist())

ct = 0x33b4ba0c3c11ad7e298b79de7261c5dd8edd7b537007b383cad9f38dbcf584e66a07c9808edad6e289516f3c6cc4186686f3a7fc8e1603e80aba601efe82e8cf2f6a28aa405cf7419b9dd1f01925c5
ct_bin = bin(ct)[2:]
ct_bin = "0" * ((len(ct_bin)//63 + 1)*63 - len(ct_bin)) + ct_bin # padding

ct_blocks = [ct_bin[i:i+63] for i in range(0, len(ct_bin), 63)]

print(f"{ct_blocks = }")

flag = ""

for block in ct_blocks:
    for i in range(len(block)):
        arr = [int(c) for c in block]
        arr[i] = arr[i] ^^ 1

        vec = vector(F, arr)

        try:
            pt = G.solve_left(vec)
            pt = "".join(map(str, pt.list()))
            flag += pt
            print(f"possible pt: {i = } {pt = } {block = }")
        except Exception as e:
            pass

print(flag)
print(long_to_bytes(int(flag, 2)))