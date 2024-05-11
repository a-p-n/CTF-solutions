from Crypto.Cipher import AES

iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\r\x0e'
key = b"yougotthekeynjoy"
ct = bytes.fromhex("69d5deb91a001151db5d98231574a51779acd1a84b9338a6750697c0af7e4591")

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = cipher.decrypt(ct)
print(pt)