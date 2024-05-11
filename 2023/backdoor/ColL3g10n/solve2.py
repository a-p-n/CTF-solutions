from pwn import remote
from hashlib import sha256
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from icecream import ic

pair1 = (bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70'),
         bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70'))
pair2 = (bytes.fromhex('4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2'),
         bytes.fromhex('4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2'))
pair3 = (bytes.fromhex('0e306561559aa787d00bc6f70bbdfe3404cf03659e704f8534c00ffb659c4c8740cc942feb2da115a3f4155cbb8607497386656d7d1f34a42059d78f5a8dd1ef'),
         bytes.fromhex('0e306561559aa787d00bc6f70bbdfe3404cf03659e744f8534c00ffb659c4c8740cc942feb2da115a3f415dcbb8607497386656d7d1f34a42059d78f5a8dd1ef'))

pairs = [pair1, pair2, pair3]

def find_collision(pair):
    m1 = pair[0]
    m2 = pair[1]
    i = 0
    while True:
        suffix = l2b(i)
        if sha256(m1 + suffix).hexdigest()[:5] == sha256(m2 + suffix).hexdigest()[:5]:
            return m1 + suffix, m2 + suffix
        i += 1

collisions = []
for pair in pairs:
    collision = find_collision(pair)
    collisions.append(collision)
    for c in collision:
        ic(c.hex())
    ic('------------------')

io = remote('34.70.212.151', 8000)
secretnums = []
for i in range(3):
    payload = b2l(b'\x7f'*10) & (int('1'*27, 2) << (27*i))
    ic(payload)
    collision = collisions[i]
    io.sendlineafter(b'first message: ', collision[0].hex().encode())
    io.sendlineafter(b'second message: ', collision[1].hex().encode())
    io.sendlineafter(b'num: ', str(payload).encode())
    io.recvuntil(b'Revealing bits : ')
    secretnums.append(ic(int(io.recvline().strip())))

secret = 0
for i in range(3):
    secret |= secretnums[i]
secret = l2b(secret).decode()
ic(secret)
io.sendlineafter(b'Guess the secret: ', secret.encode())
io.interactive()