import requests
from icecream import ic
import sys


flag=[]
f_len=len(flag)
for _ in range(1,33):
    payload=('A'*(32-_))
    payload=[x for x in payload]
    
    print('This is what is sent in hex:\n',payload)
    load=''.join(_ for _ in payload).encode('utf-8').hex()
    payload.extend(flag)
    pay=payload.copy()
    result = requests.get('https://aes.cryptohack.org//ecb_oracle//encrypt//'+load+'//')
    ct=result.json()["ciphertext"]
    for j in range(125,33,-1):
        pay.append(chr(j))
        # print('bruteforce:\n', pay)
        p=''.join(_ for _ in pay).encode('utf-8').hex()
        r = requests.get('https://aes.cryptohack.org//ecb_oracle//encrypt//'+p+'//')
        c=r.json()["ciphertext"]
        if c[:64]==ct[:64]:
            flag.append(chr(j))
            ''.join(x for x in flag)
            pay.pop()
            break
        else:
            pay.pop()
    if len(flag)==f_len:
        print('You lost')
        sys.exit()
    elif flag[-1]=='}':
        break
    else:
        f_len+=1
        print(''.join(x for x in flag))



print(''.join(x for x in flag))