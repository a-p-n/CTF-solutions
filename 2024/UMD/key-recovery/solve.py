from base64 import b64decode

def pad_base64(input):
    padding_needed = 4 - len(input) % 4
    return input + b'='*padding_needed

redacted_key = open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/UMD/key-recovery/modified.pem","rb").readlines()

data = pad_base64(b''.join((line[:-1] for line in redacted_key[1:-1])))
key = b64decode(data)
open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/UMD/key-recovery/key.bin","wb").write(key)
key = open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/UMD/key-recovery/key.bin", "rb").read()
print(key.hex())

ct = open("/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/UMD/key-recovery/out.txt" , "rb").read()
