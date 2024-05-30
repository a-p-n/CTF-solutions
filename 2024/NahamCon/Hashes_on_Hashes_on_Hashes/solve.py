from base64 import b64decode
from hashlib import md5
with open("/home/apn/Documents/bi0s/my_git/CTF-solutions/2024/NahamCon/Hashes_on_Hashes_on_Hashes/decryption_server.log" , "r") as f:
    data = f.readlines()

partial_msg_digest = []
key = ""
for i in data:

    if "Partial" in i:
        partial_msg_digest.append(i.strip().split(" ")[-1])
    elif "Received" in i:
        encrypted = b64decode(i.strip().split(" ")[-1])
    elif "expanded" in i:
        factor = int(i.strip().split(" ")[-1])
    
    elif "ready to send" in i:
        print("Enc - ", encrypted)

        decrypted = bytearray()
        for j in encrypted:
            # print(j)
            for k in range(256):
                # print(decrypted)
                if str(md5(decrypted + chr(j ^ k).encode()).hexdigest()) == partial_msg_digest[len(decrypted)]:
                    decrypted.append(j ^ k)
                    key += chr(k)
                    # print(key)
                    break
        print("DD",decrypted,key)
        partial_msg_digest.clear()



