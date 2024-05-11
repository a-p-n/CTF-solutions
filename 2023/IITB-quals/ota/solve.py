from pwn import *
from sage.all import *
from Crypto.Util.number import long_to_bytes

N = 36893488147419103259
G = 2

con = connect("0.cloud.chals.io", 18059)
con.recvline()
con.recvline()
con.recvline()

LEFT_CHUNKS , RIGHT_CHUNKS = [] , []
for i in range(64):
    line = con.recvline()
    LEFT_CHUNKS.append(long_to_bytes(int(line[len(str(i+1))+2:len(str(i+1))+21].decode())))
    RIGHT_CHUNKS.append(long_to_bytes(int(line[len(str(i+1))+22:-1].decode())))

con.recvuntil(b"Enter your choice: ")
con.sendline(b"1")
con.recvline()
x,y,z0,z1 = [],[],[],[]

for i in range(64):
    query = con.recvline()[11:-2].decode()
    query = query.split(", ")
    x.append(int(query[0]))
    y.append(int(query[1][3:]))
    z0.append(int(query[2][4:]))
    z1.append(int(query[3][4:]))

F = Zmod(N)
G = F(2)

CHOICE_BITS = ""
for i in range(64):
    X = F(x[i])
    Y = F(y[i])
    alpha = discrete_log(X,G)
    beta = discrete_log(Y,G)
    if pow(2,alpha*beta,N) == z0[i]:
        CHOICE_BITS = CHOICE_BITS + "0"
    else:
        CHOICE_BITS = CHOICE_BITS + "1"

CHOICE_BITS = int(CHOICE_BITS[::-1],2)
password = b""
for i in range(64):
    if CHOICE_BITS & (1<<i):
        password = password + RIGHT_CHUNKS[i]
    else:
        password = password + LEFT_CHUNKS[i]

con.sendline(b'2')
con.sendline(password)
con.interactive()