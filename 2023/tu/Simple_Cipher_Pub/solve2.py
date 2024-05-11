from pwn import remote, context
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from icecream import ic


def bytes2bin(msg, length=48):
    return bin(b2l(msg))[2:].zfill(length)


def bin2bytes(msg):
    return int(msg, 2).to_bytes((len(msg)+7)//8, 'big')


io = remote('chal.tuctf.com', 30004)


def encrypt(pt: bytes, key: bytes):
    io.sendline(b'1')
    io.sendlineafter(b'plaintext: ', pt)
    io.sendlineafter(b'): ', key.hex().upper().encode())
    io.recvuntil(b'is: \n')
    ct = io.recvline().strip().decode()
    ic(ct)
    return bin2bytes(ct)


def decrypt(ct: bytes, key: bytes):
    io.sendline(b'2')
    io.sendlineafter(b'binary: ', bytes2bin(ct).encode())
    io.sendlineafter(b'): ', key.hex().upper().encode())
    io.recvuntil(b'back: \n')
    pt = io.recvline().strip().decode()
    ic(pt)
    return bin2bytes(pt)


def get_pattern():
    # pattern = [9, 40, 27, 25, 42, 28, 34, 23, 17, 19, 24, 5, 11, 30, 6, 4, 41, 29, 1, 18, 16, 13, 20, 38, 36, 7, 3, 32, 12, 15, 2, 26, 14, 37, 44, 43, 22, 47, 35, 46, 8, 0, 21, 31, 33, 39, 45, 10]
    pattern = []
    for i in range(48):
        payload = ['0'] * 48
        payload[i] = '1'
        payload = ''.join(payload)
        payload = bin2bytes(payload)
        if len(payload) < 6:
            payload = payload.rjust(6, b'\x00')
        ic(payload)
        ct = bytes2bin(encrypt(payload, b'\x00' * 6))
        if ct.count('1') > 1:
            pattern.append(-1)
            continue
        pattern.append(ct.index('1'))
    for i in range(6):
        payload = b'\x00'*i + 'À'.encode() + b'\x00'*(5-i)
        ic(payload)
        ct = bytes2bin(encrypt(payload, b'\x00' * 6))
        indeces = []
        for j in range(48):
            if ct[j] == '1':
                indeces.append(j)
        for index in indeces:
            if index not in pattern:
                pattern[pattern.index(-1)] = index
    return pattern


def unscramble(bits):
    global inv_pattern
    bits = list(bits)
    op = ''
    for i in inv_pattern:
        op += bits[i]
    return op


def scramble(bits):
    global pattern
    bits = list(bits)
    op = ''
    for i in pattern:
        op += bits[i]
    return op


def xor(ptext, key):
    text = ''
    for i in range(0, 48):
        text += str(int(ptext[i]) ^ int(key[i]))
    return text


pattern = get_pattern()

inv_pattern = [0] * 48
for i in range(48):
    inv_pattern[pattern[i]] = i


flagbits = '110010100001000100101101001010111110010111001011100100100001010110111111111010001110011111011101101100000001100100001001111111110101010011110011000100000011000010000100111100011001010111010111101111100011010110100110100010010000011111100001100100100001100110100100100100110111001001010101'
key = xor(unscramble(bytes2bin(b'TUCTF{')), flagbits[:48])
ic(bin2bytes(key).hex())
blocks = [flagbits[i:i+48] for i in range(0, len(flagbits), 48)]
ptbin = ""
for block in blocks:
    ptbin += scramble(xor(block, key))
ic(bin2bytes(ptbin))
