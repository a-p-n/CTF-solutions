import base64
from string import punctuation
from itertools import product

alphabet = list(punctuation)
ct = base64.b64decode(b"1JjVq9W81a7Vk9Sd1YfVhdWN1J/VgdWF1JvVm9W31YHUn9W31YbVjdSb1YzUndW31ZzUmNW31YrUm9W31YvUmNWF1ZjVhNSb1ZDVlQ==")
pt = b"0CTF{"
for i in product(range(256), repeat=2):
    x = ("".join(map(str, i)).encode()).hex()
    if int(x, 16)^ct[0] == pt[0] and int(x, 16)^ct[1] == pt[1] and int(x, 16)^ct[2] == pt[2] and int(x, 16)^ct[3] == pt[3]:
        print(int(x, 16))
        break
key = pt[0]^ct[0]
print(hex(key))
pt = ""
for i in range(len(ct)):
    pt += chr(ct[i]^key)
print(pt)