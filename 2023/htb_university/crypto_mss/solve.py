from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii


def decrypt_flag(key, iv, enc_flag):
    cipher = AES.new(key, AES.MODE_CBC, binascii.unhexlify(iv))
    pt = cipher.decrypt(binascii.unhexlify(enc_flag))
    unpadded_pt = unpad(pt, AES.block_size)
    return unpadded_pt.decode('utf-8')  # Assuming the flag is a string

# y obtained from get_share function
y = "920638201947337273643....."
key = sha256(str(y).encode()).digest()

# iv and enc_flag obtained from encrypt_flag function
iv = "5cf0fd859d432f....."
enc_flag = "3c3e867074d74d6aa....."

decrypted_flag = decrypt_flag(key, iv, enc_flag)
print(decrypted_flag)

# https://medium.com/@ramen.doodle/htb-mss-writeup-university-ctf-2023-a305a31a20c9
# Mignotte Secret Sharing scheme