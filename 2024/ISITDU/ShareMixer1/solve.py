import hashlib

prefix = 'mXnDg7xbz354WxsP'
zeros = '0' * 6

i = 0
while True:
    i += 1
    s = prefix + str(i)
    if (hashlib.sha256(s.encode()).hexdigest()).startswith(zeros):
        print(i)
        break

