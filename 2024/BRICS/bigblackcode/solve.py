from pwn import remote
from sage.all import *

r = remote('89.169.156.185', 14647)
for _ in range(60):
    x = var('x')
    A = loads(bytes.fromhex(r.recvline().strip().decode()))
    print(A)
    B = loads(bytes.fromhex(r.recvline().strip().decode()))
    a_det = A.det()
    b_det = B.det()
    iden = 100 + _
    
    sec_idx = list(A.find(lambda x: x == iden, indices=True).keys())[0]
    new_mat = list(map(list, list(A)))
    new_mat[sec_idx[0]][sec_idx[1]] = x
    new_mat = Matrix(new_mat)
    
    secret_value = RR((new_mat.det() - b_det).roots()[0][0])
    r.sendlineafter(b"Your guess: ",str(secret_value).encode())

print(r.recvline())