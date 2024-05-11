from pwn import remote

def de_bruijn_sequence(k, n):
    try:
        alphabet = [i for i in '0123456789abcdef']
        a = [0] * k * n
        sequence = []

        def db(t, p):
            if t > n:
                if n % p == 0:
                    for j in range(1, p + 1):
                        sequence.append(alphabet[a[j]])
            else:
                a[t] = a[t - p]
                db(t + 1, p)
                for j in range(a[t - p] + 1, k):
                    a[t] = j
                    db(t + 1, t)
        db(1, 1)
        return ''.join(sequence)
    except Exception as e:
        return str(e)


db_sequence = de_bruijn_sequence(16, 4)

r = remote('accessible-sesasum-indicum.chal.irisc.tf', 10104)
r.recvuntil(b'|---|---|---|---|\n\n')

for _ in range(16):
    r.sendlineafter(b"Attempt> ", db_sequence.encode())
    r.recvline()

r.recvall()
