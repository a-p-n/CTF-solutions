from string import ascii_letters, digits, punctuation

printable = ascii_letters + digits + punctuation + " "
dat = open("/home/apn/Documents/bi0s/my_git/CTF-solutions/2024/DownUnder/three-line-crypto/passage.enc.txt", "rb").read()
popular_words = "etaoin shrdlu"

def hamming_distance_bytes(text1: bytes, text2: bytes) -> int:
    dist = 0
    for byte1, byte2 in zip(text1, text2):
        dist += bin(byte1 ^ byte2).count('1')
    return dist

def hamming_score_bytes(text1: bytes, text2: bytes) -> float:
    return hamming_distance_bytes(text1, text2) / (8 * min(len(text1), len(text2)))

l = []
for i in range(1,len(dat)):
    if hamming_score_bytes(bytes([dat[i]]), bytes([dat[0]])) < 0.38:
        l.append(i)
print(len(l))

printable_chars = []
all_chars = []
for i in range(256):
    temp = []
    for j in l:
        temp.append(bytes([dat[j] ^ i]))
    cnt = 0
    for c in temp:
        if c in printable.encode():
            cnt += 1
    printable_chars.append(cnt)
    all_chars.append(temp)
print(printable_chars.index(max(printable_chars)), max(printable_chars), all_chars[printable_chars.index(max(printable_chars))])