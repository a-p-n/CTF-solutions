from Crypto.Util.number import inverse,getRandomRange
from pwn import *
from hashlib import sha512

r = remote("crypto.2023.cakectf.com", 10444)

magic_word = b"cake_does_not_eat_cat"
p = int(r.recvline().decode().lstrip("p = "))
g = int(r.recvline().decode().lstrip("g = "))
vkey = (r.recvline().decode()).lstrip("vkey = (")
vkey = vkey[:-2]
vkey = vkey.split(", ")
print(vkey)
w , v = int(vkey[0]) , int(vkey[1])
y = v * inverse(w,p-1)

x = getRandomRange(2, p-1)
u = (w * x - 1) * inverse(v, p-1) % (p-1)

r.sendafter(b"[S]ign, [V]erify: ",b"V")
m = int(sha512(magic_word).hexdigest(),16)
s = str(pow(g,(m-1)*inverse(w,p-1),p)).encode()
t = str(pow(g,inverse(-v,p-1),p)).encode()
print(s,t)
assert 2 <= s < p
assert 2 <= t < p
r.sendafter(b"message: ", b"cake_does_not_eat_cat")
r.sendafter(b"s: ", s)
r.sendafter(b"t: ", t)
print(r.recvline())
print(r.recvline())
