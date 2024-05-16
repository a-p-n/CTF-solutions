from pwn import *
import base64
import ed25519

PHRASE = b'I want flag'

my_sk, my_vk = ed25519.create_keypair()

sig = my_sk.sign(PHRASE)
sig = base64.b64encode(sig)

io = remote("hsm.rumble.host", 3229)

io.sendlineafter(b"> ", b"1")

key = io.recvline()
key = base64.b64decode(key[13:-1])

forged_key = key[:60] + my_sk.sk_s[32:]
forged_key = base64.b64encode(forged_key)

io.sendlineafter(b"> ", b"3")
io.sendlineafter(b": ", forged_key)
io.sendlineafter(b": ", PHRASE)
io.sendlineafter(b": ", sig)

io.interactive()