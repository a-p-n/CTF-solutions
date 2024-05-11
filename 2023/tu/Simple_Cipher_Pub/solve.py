from pwn import *
from icecream import ic

def pad(ptext):
    if len(ptext) % 48 != 0:
        bitsToAdd = 48-(len(ptext) % 48)
        add = ('0'*bitsToAdd)
        ptext += add
    elif len(ptext) == 0:
        ptext = ('0'*48)
    return ptext

def xor(ptext, key):
    text = ''
    for i in range(0, 48):
        text += str(int(ptext[i]) ^ int(key[i]))
    return text

def substitution(ptkey):
    substituted_pt = xor(ptkey, binKey)
    return substituted_pt.find('1')


r = remote('chal.tuctf.com', 30004)
r.recvuntil(b'''                    \n''')
r.sendline(b'1')

pt = ''
for i in range(48):
    pt 

key = '0011AABBCCDD'
r.sendlineafter(b'Enter your plaintext: ', pt.encode())
r.sendlineafter(b'Enter your 6 byte key (ex. 0011AABBCCDD): ', key.encode())
r.recvline()
r.recvline()

binCT = r.recvline().decode().strip()
binKey = str(bin(int('1'+key, base=16)))[3:]
binpt = ''
for i in pt:
    binpt += '{0:08b}'.format(ord(i))

pattern = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
ind = -1
for i in range(0, len(binCT), 48):
    pattern_ind = substitution(binCT[i:i+48])
    if pattern_ind == -1:
        continue
    pattern[ind] = pattern_ind
    ind -= 1
    
print(pattern)

# scrambled = ''
# for i in range(0, len(binpt), 48):
#     _48bit = binpt[i:i+48]
#     for j in pattern:
#         scrambled += str(_48bit[j])

r.sendline(b'2')
r.sendlineafter(b'Enter your ciphertext as binary (ex. 0011001101010101000011110000000011111111): ', binCT.encode())
r.sendlineafter(b'Enter your 6 byte key (ex. 0011FFDDCCBB): ', key.encode())
r.recvline()
r.recvline()

PT = r.recvline().decode().strip()

# revPattern=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
# ind = -1
# for i in range(0, len(binCT), 48):
#     substituted_pt = substituted_pt + xor(binCT[i:i+48], binKey)
#     if (substituted_pt.find('1', i, i + 48)) == -1:
#         continue
#     revPattern[ind] = (substituted_pt.find('1', i, i + 48)) % 48
#     ind -= 1
# print(revPattern)
# r.interactive()
# r.recvuntil(b'''                    \n''')

def find_revpattern(pattern, binpt):
    revPattern=[0]*48
    ind = -1
    for i in range(0, len(binCT), 48):
        substituted_pt = xor(binpt[i:i+48], binKey)
        if (substituted_pt.find('1', i, i + 48)) == -1:
            continue
        revPattern[ind] = (substituted_pt.find('1', i, i + 48)) % 48
        ind -= 1
    return revPattern