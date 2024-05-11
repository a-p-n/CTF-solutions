with open("flag.enc","rb") as f1:
    data = f1.read()

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
i = 0xcafed3adb3ef1e37
while True:
    key = (i).to_bytes(32,"big")
    iv = b"r4nd0m_1v_ch053n"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc = cipher.decrypt(pad(data,AES.block_size))
    if b"PNG" in enc and b"IDAT" in enc and b"IHDR" in enc and b"IEND" in enc:
        print(enc,i)
        break
    i+=i
