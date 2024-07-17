from pwn import remote, xor

io = remote('2024.ductf.dev', 30020)

known = b''
while len(known) < 4: 
    for i in range(256):
        io.sendlineafter(b'ct: ', (known.hex() + bytes([i]).hex()).encode())
        response = io.recvline()
        if response.strip() == b'1'*(len(known)+1):
            known += bytes([i])
            break
    
io.sendlineafter(b'ct: ', xor(known, b'1111', b'FLAG').hex().encode())
print(io.recvline().decode())