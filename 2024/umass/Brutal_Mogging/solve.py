from binascii import unhexlify
from itertools import product
from hashlib import sha256

def xor(data1, data2):
    return bytes([data1[i] ^ data2[i] for i in range(len(data1))])

def do_round(data, key):
    m = sha256()
    m.update(xor(data[2:4], key))
    return bytes(data[2:4]) + xor(m.digest()[0:2], data[0:2])

def do_round_inv(data, key):
    m = sha256()
    m.update(xor(data[0:2], key))
    return xor(m.digest()[0:2], data[2:4]) + bytes(data[0:2])

def pad(data):
    padding_length = 4 - (len(data) % 4)
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_block(data, key):

    for i in range(10):
        data = do_round(data, key)
    return data

def decrypt_block(data, key):
    for i in range(10):
        data = do_round_inv(data, key)
    return data

def encrypt_data(data, key):
    cipher = b''
    while data:
        cipher += encrypt_block(data[:4], key)
        data = data[4:]
    return cipher

def decrypt_data(cipher, key):
    data = b''
    while cipher:
        data += decrypt_block(cipher[:4], key)
        cipher = cipher[4:]
    return data

def encrypt(data, key):
    data = pad(data)
    return encrypt_data(encrypt_data(data, key[0:2]), key[2:4])

def decrypt(data, key):
    plain = decrypt_data(decrypt_data(data, key[2:4]), key[0:2])
    return unpad(plain)


enc_flag = unhexlify("d41e3cdae4f92dd03495ba6920aaa0286ec019f0646e1e8218147731bfe0c2b6037845345e3ebaf5cf1be8df183f2e34")
plain, cipher = pad(b"aaaa"), unhexlify("c691e5f514296010")

key_1 = product(range(256), repeat=2)
ciphers = {}
for i in key_1:
    ciphers[encrypt_data(plain, bytes(i))] = bytes(i)

key_2 = product(range(256), repeat=2)
pts = {}
for i in key_2:
    if decrypt_data(cipher, bytes(i)) in list(ciphers.keys()):
        key = (ciphers[decrypt_data(cipher, bytes(i))]+bytes(i))
        print("Key found" , key)
        print(decrypt(enc_flag, key))
        break
