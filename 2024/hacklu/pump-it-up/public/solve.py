with open("flag.enc","rb") as f:
    enc = f.read()

flag =  b"flag{y0u_"
flag_hex =  flag.hex()

dic = {}
for i in range(0, 192216 * len(flag_hex), 192216):
    for j in range(i, i + 192216, 8):
        dic[enc[j : j + 8]] = flag_hex[i // 192216]


for i in range(16, 192216, 8):
    for j in range(192216 + 8, 192216 * 2, 8):
        if enc[i : i + 8] == enc[j : j + 8]:
            print(i,j)