from pwn import remote, xor

con = remote('chall.lac.tf', 32222)
con.recvuntil(b"Can you guess the secret?\n")

empty, null_bytes = b"", b"\x00"*16
macs = []

con.sendline(b"1")
con.sendlineafter(b"input > ", empty)
con.sendlineafter(b"input > ", empty)
macs.append(bytes.fromhex(con.recvline().strip()).decode())

con.sendline(b"1")
con.sendlineafter(b"input > ", null_bytes)
con.sendlineafter(b"input > ", empty)
macs.append(bytes.fromhex(con.recvline().strip()).decode())

con.sendline(b"1")
con.sendlineafter(b"input > ", empty)
con.sendlineafter(b"input > ", null_bytes)
macs.append(bytes.fromhex(con.recvline().strip()).decode())

# con.sendline(b"1")
# con.sendlineafter(b"input > ", null_bytes)
# con.sendlineafter(b"input > ", null_bytes)
# macs.append(bytes.fromhex(con.recvline().strip()).decode())

secret = xor(macs[0], macs[1], macs[2], macs[3])

con.sendline(b"2")
con.sendlineafter(b"guess > ", secret)
con.interactive()