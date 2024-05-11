from pwn import remote, context
from icecream import ic
from string import ascii_uppercase as alf

io = remote('chal.tuctf.com', 30007)

def reset_connection():
    global io
    io = remote('chal.tuctf.com', 30007)

def get_mapping(levelnum=0):
    print(io.recvuntil(b'What level? ').decode())
    io.sendline(str(levelnum).encode())
    io.sendlineafter(b'text:\n', alf.encode())
    mapping = dict(zip(io.recvline().decode().strip().split()[3:], alf))
    io.recvuntil(b'slow!')
    return mapping

def get_mapping_long():
    # mapping = dict()
    # for c in alf:
    #     try:
    #         io.recvuntil(b'What level? ').decode()
    #         io.sendline(str(levelnum).encode())
    #         io.sendlineafter(b'text:\n', c.encode())
    #         mapping[io.recvline().decode().strip().split()[3]] = ic(c)
    #         io.recvuntil(b'slow!')
    #     except EOFError:
    #         reset_connection()
    # return mapping
    return {'SwiftSwiftTaylorTaylorSwift': 'D',
    'SwiftSwiftTaylorTaylorTaylor': 'C',
    'SwiftTaylorSwiftSwiftSwift': 'B',
    'SwiftTaylorSwiftSwiftTaylor': 'A',
    'SwiftTaylorSwiftTaylorSwift': 'Z',
    'SwiftTaylorSwiftTaylorTaylor': 'Y',
    'SwiftTaylorTaylorSwiftSwift': 'X',
    'SwiftTaylorTaylorSwiftTaylor': 'W',
    'SwiftTaylorTaylorTaylorSwift': 'V',
    'SwiftTaylorTaylorTaylorTaylor': 'U',
    'TaylorSwiftSwiftSwiftSwift': 'T',
    'TaylorSwiftSwiftSwiftTaylor': 'S',
    'TaylorSwiftSwiftTaylorSwift': 'R',
    'TaylorSwiftSwiftTaylorTaylor': 'Q',
    'TaylorSwiftTaylorSwiftSwift': 'P',
    'TaylorSwiftTaylorSwiftTaylor': 'O',
    'TaylorSwiftTaylorTaylorSwift': 'N',
    'TaylorSwiftTaylorTaylorTaylor': 'M',
    'TaylorTaylorSwiftSwiftSwift': 'L',
    'TaylorTaylorSwiftSwiftTaylor': 'K',
    'TaylorTaylorSwiftTaylorSwift': 'J',
    'TaylorTaylorSwiftTaylorTaylor': 'I',
    'TaylorTaylorTaylorSwiftSwift': 'H',
    'TaylorTaylorTaylorSwiftTaylor': 'G',
    'TaylorTaylorTaylorTaylorSwift': 'F',
    'TaylorTaylorTaylorTaylorTaylor': 'E'}

def level0to3(levelnum):
    print(io.recvuntil(b'What level? ').decode())
    io.sendline(str(levelnum).encode())
    io.sendlineafter(b'text:\n', alf.encode())
    mapping = dict(zip(io.recvline().decode().strip().split()[3:], alf))
    ic(mapping)
    for i in range(30):
        io.recvline()
        ct = io.recvline().decode().split()[1:]
        pt = ''.join([mapping[c] for c in ct])
        io.sendline(ic(pt).encode())
        _ = [io.recvline() for __ in range(2)]

def getshuffleorder(n):
    # global mapping
    # og = alf[:n]
    # io.recvuntil(b'What level? ')
    # io.sendline(b'4')
    # io.sendlineafter(b'text:\n', og.encode())
    # ct = io.recvline().decode().strip().split()[3:]
    # pt = ''.join([mapping[c] for c in ct])
    # shuffle_order = [pt.index(c) for c in og]
    # return shuffle_order
    shuffle_orders = {
       2 : [0, 1],
       3 : [0, 1, 2],
       4 : [0, 1, 3, 2],
       5 : [0, 2, 4, 3, 1],
       6 : [0, 2, 5, 3, 1, 4],
       7 : [0, 2, 5, 3, 1, 4, 6],
       8 : [0, 2, 6, 3, 1, 4, 7, 5],
       9 : [0, 3, 7, 4, 1, 5, 8, 6, 2],
       10 : [0, 3, 8, 4, 1, 5, 9, 6, 2, 7],
       11 : [0, 3, 8, 4, 1, 5, 9, 6, 2, 7, 10],
       12 : [0, 3, 9, 4, 1, 5, 10, 6, 2, 7, 11, 8],
       13 : [0, 4, 10, 5, 1, 6, 11, 7, 2, 8, 12, 9, 3],
       14 : [0, 4, 11, 5, 1, 6, 12, 7, 2, 8, 13, 9, 3, 10]
    }
    return shuffle_orders[n]

def getshuffleorder_long(n):
    mapping = get_mapping_long()
    og = alf[:n]
    io.recvuntil(b'What level? ')
    io.sendline(b'7')
    io.sendlineafter(b'text:\n', og.encode())
    ct = io.recvline().decode().strip().split()[3:]
    pt = ''.join([mapping[c] for c in ct])
    shuffle_order = [pt.index(c) for c in og]
    return shuffle_order

def level4():
    global mapping, shuffle_orders
    shuffle_orders = [ic(getshuffleorder(n)) for n in range(2, 15)]
    print(io.recvuntil(b'What level? ').decode())
    io.sendline(b'4')
    io.sendlineafter(b'text:\n', alf.encode())
    _ = dict(zip(io.recvline().decode().strip().split()[3:], alf))
    for i in range(30):
        io.recvline()
        ct = io.recvline().decode().split()[1:]
        shuffle_order = shuffle_orders[len(ct)-2]
        pt = [mapping[c] for c in ct]
        pt = ''.join([pt[shuffle_order[i]] for i in range(len(pt))])
        io.sendline(ic(pt).encode())
        _ = [io.recvline() for __ in range(2)]

def level7():
    mapping = get_mapping_long()
    shuffle_orders = [ic(getshuffleorder_long(n)) for n in range(2, 15)]
    for i in range(30):
        io.recvline()
        ct = io.recvline().decode().split()[1:]
        shuffle_order = shuffle_orders[len(ct)-2]
        pt = [mapping[c] for c in ct]
        pt = ''.join([pt[shuffle_order[i]] for i in range(len(pt))])
        io.sendline(ic(pt).encode())
        _ = [io.recvline() for __ in range(2)]

mapping = get_mapping()
shuffle_orders = [ic(getshuffleorder(n)) for n in range(2, 15)]
for i in range(4):
    level0to3(i)
level4()
level0to3(5)
level0to3(6)
level7()
io.interactive()