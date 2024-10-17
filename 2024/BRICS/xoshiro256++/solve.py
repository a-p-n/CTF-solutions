from string import printable

flag = b"brics+{"
with open("output.txt", "r") as f:
    lines = f.readlines()
    for line in range(len(lines)):
        lines[line] = bytes.fromhex(lines[line].strip())

ind = 7
for i in lines:
    l = []
    for j in lines:
        print(i[ind] ^ j[ind])
        if chr(i[ind] ^ j[ind]) in printable:
            l.append(bytes(i ^ j))
    print(l)
