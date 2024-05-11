from pwn import remote

pt = (b"a"*16).hex()[2:].encode()
for i in range(0x1169, 0x11ed):
    for j in range(8):
        r = remote('139.162.24.230', 31339)
        r.sendline(pt + b" " + str(i).encode() + b" " + str(j).encode())
        try :
            ct = r.recvline()
            print(ct)
            r.sendline(ct)
            print(r.recvall())
            r.close()
        except:
            r.close()
