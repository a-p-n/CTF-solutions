from pwn import *

io = remote('chall.polygl0ts.ch', 9068)

io.recvuntil(b'What circuit size are you interested in ?')
io.sendline(b'3')

correct = 0

while correct < 32:
    l = []
    for i in [0, 1, 2, 4, 8, 16, 32]:
        io.recvuntil(b'[1] check bit\n[2] test input\n')
        io.sendline(b'2')
        io.recvuntil(b'input: ')
        io.sendline(f'{i}'.encode())
        response = io.recvline().decode().strip()
        l.append(int(response.split('=')[-1]))
    if len(l) - len(set(l)) > 1:
        bit = 1
    else:
        bit = 0
    
    io.recvuntil(b'[1] check bit\n[2] test input\n')
    io.sendline(b'1')
    io.recvuntil(b'bit: ')
    io.sendline(f'{bit}'.encode())
    
    correct += 1
    print(f'Correct: {correct}')

io.interactive()
# EPFL{r4nd0m_c1rcu1t5_4r3_n0_g00d_rngs??}
