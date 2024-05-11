from Crypto.PublicKey import RSA

a = open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/tamu/jumbled/public","r").read().split()
public_key = RSA.importKey("".join(chr(int(i, 16)) for i in a))
n = public_key.n
e = public_key.e

private = ("".join(chr(int(i, 16)) for i in open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/tamu/jumbled/private", "r").read().split()))
l = [private[i:i+10] for i in range(0, len(private), 10)]

mapping = {0: 8, 1: 6, 2: 9, 3: 5, 4: 7, 5: 3, 6: 1, 7: 4, 8: 0, 9: 2}
for i in range(len(l)):
    st = ""
    for j in range(len(l[i])):
        st += str(mapping[l[i][j]])
    l[i] = st

private = "".join(l)
print(private)

l = [private[i:i+10] for i in range(0, len(private), 10)]
