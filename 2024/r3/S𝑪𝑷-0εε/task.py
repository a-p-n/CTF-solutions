from hashlib import sha256

with open("██████████.jpg","rb") as f:
    HHH = sha256()
    HHH.update(f.read())
    flag = "R3CTF{"+ HHH.hexdigest() + "}"
