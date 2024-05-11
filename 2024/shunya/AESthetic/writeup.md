# Rivest Salted Adleman

We are given a ciphertext , p (which is a prime factor of n), e , salted_q and salted_n (I am not sure about it but they are not actual q and n, some bits of their bits have been changed).

Since the length of flag is less than p, we can retireve the flag just by decrypting it with p.

```py
# c = m^e mod n
# n = p*q
# m = c^d mod n
# d = pow(e,-1,(p-1)*(q-1))
# if len(c) < p --> m = c^d mod p and d = pow(e,-1,p-1)

from Crypto.Util.number import long_to_bytes

c = 332390996033761218977578960091058900061139210257883065481008023465866203213646838419152404854307189904898248026722555965488045307811040694129009535565921

p = 95224848836921243754124073456831190902097637702298493988505946669357481749059

salted_q = 62480590829144807189161429469255353976579455660965599518063804867866301233320

salted_n = 5949704816946842021797594696485093255706996345339732550774644373410311670577880550185915164563052783086742129032939489765553432924892778486382904377417840

e = 65537

long_to_bytes(pow(c,pow(e,-1,p-1),p))
# FLAG : 0CTF{4sa_1s_l0v3}
```

# AESthetic challenge

We are provided with 2 wav files, "aud1_IV.wav" and "aud2_k.wav". From the name we can say that its IV and KEY respectively. We are also given a ciphertext. The flag is encrypted using AES (from the challenge name) and the mode used is CBC as it needs both KEY and IV to encrypt.

After hearing the .wav file, we understood that it is morse code. We used https://morsecode.world/international/decoder/audio-decoder-adaptive.html to decode the morse code.

From "aud2_k.wav" we got --> yougotthekeynjoy
From "aud1_IV.wav" we got --> 0x000102030405060708090a0b0c0d0e0f

So we got the IV and the KEY. Key is in hex so converted it into bytes and then decrypted it.

```py
from Crypto.Cipher import AES
iv = 0x000102030405060708090a0b0c0d0e0f
iv = b"\x00" + long_to_bytes(iv)
key = b"yougotthekeynjoy"
ct = bytes.fromhex("69d5deb91a001151db5d98231574a51779acd1a84b9338a6750697c0af7e4591")

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = cipher.decrypt(ct)
print(pt)

# FLAG : 0CTF{d4sh_und3rsc0r3_d0t!}
```
# Echoes of Encryption

We are given a code which encrypts the flag by xoring each character of the flag with each character of the key. The key is generated randomly after setting the value of the seed to a fixed number.

## Description
In December 2022, my friend Alok's device was hacked. Upon investigation, he discovered that the breach was due to a vulnerability in the Nvidia SMC which had been recently discovered and published for research purposes on the same day he was hacked.

From the description, we know that there was a vulnerability in the Nvidia SMC in around December 2022. So we searched for that vulnerability and found a cve, https://nvd.nist.gov/vuln/detail/CVE-2022-42269 . As a seed should be a number we tried to put the cve number(At first we tried to put the date on which this was discovered but didn't work).

Xor's property:
A xor B = C implies,
C xor B = A

Using this property, we recovered the flag.

## Chall file:
```py
import random
import string

def encrypt_string(input_string, seed):
    random.seed(seed)
    
    allowed_chars = string.ascii_letters + string.digits
    key = ''.join(random.choices(allowed_chars, k=len(input_string)))
    encrypted_string = ''
    for i in range(len(input_string)):
        encrypted_char = chr(ord(input_string[i]) ^ ord(key[i]))
        encrypted_string += encrypted_char
    return encrypted_string.encode().hex()


seed_value = 
input_string = ""
encrypted = encrypt_string(input_string, seed_value)
```
## Solve Script:
```py
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

# FLAG : 0CTF{alw4y5_r3ad_7he_d3scr!pti0n_c4r3fully}
```