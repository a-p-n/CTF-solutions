from pwn import *
from hashlib import sha1

characters = string.digits + string.ascii_lowercase[:6]

con = connect("152.136.172.227",22222)
PoW,hash = con.recvline().decode().lstrip('sha1(prefix+"').split('")==')
con.recvline()

while True:
    prefix = ''.join(random.choices(characters, k=6)).encode()
    if sha1(prefix+PoW.encode()).hexdigest() == hash:
        print(prefix)
        con.sendline(prefix)
        break

pos = con.recv().decode().lstrip("i am at ").rstrip(", claw me.\nYour moves: ")
con.send(b"")
con.recvline()