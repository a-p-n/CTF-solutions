from Crypto.Cipher import AES
from json import loads
from pwn import remote
from binascii import hexlify, unhexlify

# r = remote('integral-communication.chal.irisc.tf', 10103)
# r.sendlineafter(b'---------------------------------------------------------------------------\n> ',b"1")
# r.sendlineafter(b"Please enter your message: ",b" 'messa'}{'from': 'admin', 'act': 'flag', 'msg': 'messa'}")
# x = r.recvline()
# iv = r.recvline()[4:-1]
# command = r.recvline()[9:-1]
# print(command,len(command))
# r.sendlineafter(b'---------------------------------------------------------------------------\n> ', b"2")
# r.sendlineafter(b"IV: ", command[48:64])
# r.sendlineafter(b"Command: ", command[64:])
# print(r.recvline())
# r.interactive()

r = remote('integral-communication.chal.irisc.tf', 10103)
r.sendlineafter(b'---------------------------------------------------------------------------\n> ', b"1")
r.sendlineafter(b"Please enter your message: ",b"'messa'}{'from': 'admin', 'act': 'flag', 'msg': 'messa'")
r.recvline()
iv = r.recvline()[4:-1]
command = r.recvline()[9:-1]
print(command, len(command))
print(unhexlify(command), unhexlify(command[112:]))
r.sendlineafter(b'---------------------------------------------------------------------------\n> ', b"2")
r.sendlineafter(b"IV: ", command[64:97])
r.sendlineafter(b"Command: ", command[97:])
print(r.recvline())
r.interactive()
