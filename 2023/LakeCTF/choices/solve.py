from pwn import process
import itertools
from tqdm import tqdm
import random
prog = open('plus_obf', 'rb').read()

def patch(n):
    target = b'\xba\x1d\x00\x00\x00'
    patched = b'\xba' + bytes([n]) + b'\x00\x00\x00'
    open('plus_obf_patched', 'wb').write(prog.replace(target, patched))

def gen_rest(inside, group):
    group_dict = {c: group.count(c) for c in set(group)}
    out = ""
    for c in inside:
        if c not in group_dict:
            out += c * inside[c]
        else:
            out += c * (inside[c] - group_dict[c])
    return out

def is_bad(inside, group):
    group_dict = {c: group.count(c) for c in set(group)}
    for c in group_dict:
        if inside[c] < group_dict[c]:
            return True
    return False

BANNED = [
    'EPFL{3z_dm',
    # 'EPFL{3z_e',
    # # 'EPFL{3z_a8',
]
def solve(known, inside):
    known_n = len(known) // 2
    for group in tqdm(list(itertools.product(inside, repeat=2))):
    # for group in list(itertools.product(inside, repeat=2)):
        if is_bad(inside, group):
            continue
        patch(known_n + 1)
        rest = gen_rest(inside, group)
        rest = list(rest)
        random.shuffle(rest)
        rest = ''.join(rest)
        guess = known + ''.join(group) + rest + '}'
        p = process(['./plus_obf_patched'], level='error')
        p.sendline(guess.encode())
        line = p.recvline()
        p.close()
        if b'SUCCESS' in line:
            # if known + ''.join(group) in BANNED:
            if any(guess.startswith(b) for b in BANNED):
                continue
            # known = known + ''.join(group)
            print(known_n + 1, guess)
            inside_tmp = inside.copy()
            for c in group:
                inside_tmp[c] -= 1
                if inside_tmp[c] == 0:
                    del inside_tmp[c]

            if not inside_tmp:
                return guess
            else:
                # continue    
                worked = solve(known + ''.join(group), inside_tmp)
                if worked:
                    return worked
    return False


# patch(5)
# exit()

known = 'EPFL{3z_di'
inside = '33344445568EFLP___________aaadeeefhhiillmnnrsttttvwzzz'
inside = {
    c: inside.count(c) for c in set(inside)
}
for c in set(known):
    if c in inside:
        inside[c] -= known.count(c)
        if inside[c] == 0:
            del inside[c]

print(inside)

print(solve(known, inside))
