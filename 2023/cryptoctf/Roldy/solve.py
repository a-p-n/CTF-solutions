from pwn import remote

io = remote('06.cr.yp.toc.tf', 31377)
for _ in range(6):
    print(io.recvline().decode(),end='')
for _ in range(4):
    io.recvline()
io.sendline(b'E')

flag_enc = eval(io.recvline().split(b'=')[1])
print(flag_enc)

lower = [0]*len(flag_enc)
upper = [2**128 - 1]*len(flag_enc)
mid = [(i+j)//2 for i,j in zip(lower,upper)]

def ltobytes(l):
    return b''.join([i.to_bytes(16,'big') for i in l])

def update_mid(got):
    global upper,lower,mid
    for i in range(len(got)):
        if got[i] < flag_enc[i]:
            upper[i] = mid[i]
            mid[i] = (mid[i] + lower[i])//2
        else:
            lower[i] = mid[i]
            mid[i] = (mid[i] + upper[i])//2

while True:
    for _ in range(4):
        io.recvline()
    payload = ltobytes(mid)
    print(payload)
    io.sendline(b'T')
    io.recvline()
    io.sendline(payload)
    gotx = io.recvline()
    try:
        got = eval(gotx.split(b'=')[1])
    except:
        print(gotx)
        break
    update_mid(got)
    if got == flag_enc:
        break
    
print(ltobytes(mid))