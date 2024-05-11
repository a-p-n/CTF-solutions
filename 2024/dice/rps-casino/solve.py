from pwn import *

pty = process.PTY
#r = process(['python', 'server.py'], stdin=pty, stdout=pty, stderr=open('kek', 'w'))
r = remote('mc.ax', 31234)

r.recvline()
rems = []
for _ in range(56):
    r.sendline(b'rock')
    res = r.recvuntil(b'!\n')
    rem = 0 if res.strip().endswith(b'Tie!') else 2 if res.strip().endswith(b'win!') else 1
    rems.append(rem)

states1 = []
for i in range(16):
    states1.append(set(filter(lambda n: n % 3 == rems[i], range(16))))

def next_st(s1, s2):
    b1 = (s1 ^ (s1 >> 1) ^ (s1 >> 3) ^ s2) & 1
    b2 = ((s1 >> 1) ^ (s1 >> 2) ^ s2 ^ (s2 >> 1)) & 1
    b3 = ((s1 >> 2) ^ (s1 >> 3) ^ (s2 >> 1) ^ (s2 >> 2)) & 1
    b4 = ((s1 >> 3) ^ s2 ^ (s2 >> 2) ^ (s2 >> 3)) & 1
    return b1 | (b2 << 1) | (b3 << 2) | (b4 << 3)

states2 = []
for i in range(len(states1) - 1):
    states2.append([])
    for s1 in states1[i]:
        for s2 in states1[i + 1]:
            if next_st(s1, s2) % 3 == rems[16 + i]:
                states2[-1].append((s1, s2))

states3 = []
for i in range(len(states2) - 1):
    states3.append([])
    for s1 in states2[i]:
        for s2 in states2[i + 1]:
            if s1[1] == s2[0]:
                st1, st2, st3 = s1[0], s1[1], s2[1]
                if next_st(next_st(st1, st2), next_st(st2, st3)) % 3 == rems[32 + i]:
                    states3[-1].append((st1, st2, st3))


def extend_states(states):
    new_states = []
    for i in range(len(states) - 1):
        new_states.append([])
        for s1 in states[i]:
            for s2 in states[i + 1]:
                if s1[1:] == s2[:-1]:
                    new_states[-1].append(s1[:1] + s2)
    return new_states

states = states3
while len(states) > 1:
    states = extend_states(states)





def LFSR(state):
    state = state
    j = 0
    while 1:
        j += 1
        yield state & 0xf
        for i in range(4):
            bit = (state ^ (state >> 1) ^ (state >> 3) ^ (state >> 4)) & 1
            state = (state >> 1) | (bit << 63)


def get_state(st):
    state = 0
    for i, n in enumerate(st):
        state |= (n << (4 * i))
    return state

print('states:', states)
ng = None
for st in states[0]:
    rng = LFSR(get_state(st))
    for rem in rems:
        if next(rng) % 3 != rem:
            break
    else:
        ng = rng
        print('final state:', st)
        break

rps = ["rock", "paper", "scissors", "rock"]
for _ in range(50):
    r.sendline(rps[next(ng) % 3 + 1].encode())
r.interactive()