from Crypto.Util.number import bytes_to_long
import numpy as np
from key_expansion import expand_key
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import signal

FLAG = os.getenv("FLAG", "flag{this_is_a_fake_flag}")

#########################################################################################
# This code is based on the following sources: https://cryptohack.org/
#########################################################################################

N_ROUNDS = 10

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
iv = cipher.iv


def matrix2bytes(matrix):
    """Converts a 4x4 matrix into a 16-byte array."""
    text = b""
    for line in matrix:
        for n in line:
            text += bytes([n])
    return text


def add_round_key(s, k):
    return [[s[i][j] ^ k[i][j] for j in range(4)] for i in range(4)]


def concat(a, b):
    tmp = int("{:064b}".format(a) + "{:064b}".format(b), 2)
    tmp_bin_list = [int(n) for n in bin(tmp)[2:]]
    irreducible_poly = [1, 0, 0, 0, 1, 1, 0, 1, 1]
    res = np.polydiv(tmp_bin_list, irreducible_poly)[1]
    res = list(map(int, res))
    res = [x % 2 for x in res]
    res = "".join(map(str, res))
    res = int(res, 2)
    return res


def sub_bytes(s, round_key):
    for i, line in enumerate(s):
        for j, x in enumerate(line):
            k = bytes_to_long(matrix2bytes(round_key))
            res = concat(k, s[i][j])
            assert concat(k, res) == s[i][j]
            s[i][j] = res

    return s


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


def bytes2matrix(text):
    return [list(text[i : i + 4]) for i in range(0, len(text), 4)]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def decrypt(key, ciphertext):
    round_keys = expand_key(key, N_ROUNDS)

    state = bytes2matrix(ciphertext)
    state = add_round_key(state, round_keys[N_ROUNDS])

    for i in range(N_ROUNDS - 1, -1, -1):
        inv_shift_rows(state)
        state = sub_bytes(state, round_keys[i + 1])
        state = add_round_key(state, round_keys[i])
        if i > 0:
            inv_mix_columns(state)

    plaintext = matrix2bytes(state)
    return plaintext


def encrypt(key, plaintext):
    round_keys = expand_key(key, N_ROUNDS)

    state = bytes2matrix(plaintext)
    state = add_round_key(state, round_keys[0])

    for i in range(1, N_ROUNDS):
        state = sub_bytes(state, round_keys[i])
        shift_rows(state)
        mix_columns(state)
        state = add_round_key(state, round_keys[i])

    state = sub_bytes(state, round_keys[N_ROUNDS])
    shift_rows(state)
    state = add_round_key(state, round_keys[N_ROUNDS])

    ciphertext = matrix2bytes(state)
    assert bytes2matrix(ciphertext) == state
    return ciphertext


# AES CBC
def AES_CBC_encrypt(key, iv, plaintext):
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        block = plaintext[i : i + 16]
        if len(block) < 16:
            block += b"\x00" * (16 - len(block))
        block = bytes([block[j] ^ iv[j] for j in range(16)])
        block = encrypt(key, block)
        ciphertext += block
        iv = block
    return ciphertext


def AES_CBC_decrypt(key, iv, ciphertext):
    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        block = decrypt(key, block)
        block = bytes([block[j] ^ iv[j] for j in range(16)])
        plaintext += block
        iv = ciphertext[i : i + 16]
    # Remove padding
    plaintext = plaintext.rstrip(b"\x00")
    return plaintext


if __name__ == "__main__":
    key = get_random_bytes(16)
    signal.alarm(120)
    for i in range(2):
        print("You have two options: \n1. Encrypt a message\n2. Retrive ecrypted flag")
        option = int(input("Enter your option: "))
        if option == 1:
            plain_text = input("Enter the message you want to encrypt: ")
            iv = get_random_bytes(16)
            cipher_text = AES_CBC_encrypt(key, iv, plain_text.encode("utf-8"))
            assert AES_CBC_decrypt(key, iv, cipher_text) == plain_text.encode("utf-8")
            print(f"Encrypted message: {cipher_text}")
            print(f"iv: {iv}")
        elif option == 2:
            iv = get_random_bytes(16)
            ecrypted_flag = AES_CBC_encrypt(key, iv, FLAG.encode("utf-8"))
            assert AES_CBC_decrypt(key, iv, ecrypted_flag) == FLAG.encode("utf-8")
            print(f"Encrypted flag: {ecrypted_flag}")
            print(f"iv: {iv}")
        else:
            print("Invalid option")
            exit(0)
    print("bye:)")
