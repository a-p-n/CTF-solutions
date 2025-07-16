from pwn import remote, context, xor

context.log_level = "debug"
r = remote("0.cloud.chals.io", 26625)

x = r.recvline()
print(x)
r.sendline(b"1")
x = r.recvline()
print(x)
r.recvline()