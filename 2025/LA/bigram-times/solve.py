characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}~_"

def bigram_multiplicative_shift(bigram):
    assert(len(bigram) == 2)
    pos1 = characters.find(bigram[0]) + 1
    pos2 = characters.find(bigram[1]) + 1
    shift = (pos1 * pos2) % 67
    return characters[((pos1 * shift) % 67) - 1] + characters[((pos2 * shift) % 67) - 1]

def decrypt_bigram(encrypted_bigram):
    possible_bigrams = []
    for c1 in characters:
        for c2 in characters:
            bigram = c1 + c2
            if bigram_multiplicative_shift(bigram) == encrypted_bigram:
                possible_bigrams.append(bigram)
    return possible_bigrams

def decrypt_flag(shifted_flag):
    decrypted_flag = ""
    for i in range(0, len(shifted_flag), 2):
        encrypted_bigram = shifted_flag[i:i+2]
        possible_bigrams = decrypt_bigram(encrypted_bigram)
        if possible_bigrams:
            decrypted_flag += possible_bigrams[0]
        else:
            decrypted_flag += "??"
    return decrypted_flag

shifted_flag = "jlT84CKOAhxvdrPQWlWT6cEVD78z5QREBINSsU50FMhv662W"

decrypted_flag = decrypt_flag(shifted_flag)
print("Decrypted Flag:", decrypted_flag)