import random
import string

def decrypt_string(input_string, seed):
    random.seed(seed)

    allowed_chars = string.ascii_letters + string.digits
    key = ''.join(random.choices(allowed_chars, k=len(input_string)))
    decrypted_string = ''
    for i in range(len(input_string)):
        decrypted_char = chr((input_string[i]) ^ ord(key[i]))
        decrypted_string += decrypted_char
    return decrypted_string.encode()

input_string = bytes.fromhex("5e04610a22042638723c571e1a5436142764061f39176b4414204636251072220a35583a60234d2d28082b")
print(decrypt_string(input_string, 202242269))
