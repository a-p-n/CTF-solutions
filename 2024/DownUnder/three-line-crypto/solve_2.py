from string import printable
import string
import matplotlib.pyplot as plt
from collections import Counter
from typing import List, Tuple

dat = open('/home/apn/Documents/bi0s/my_git/CTF-solutions/2024/DownUnder/three-line-crypto/new_out.txt','rb').read()

def single_byte_xor(text: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in text])

def plot_linears(dist_1, dist_2, title=None):
    plt.plot(list(string.ascii_lowercase), dist_1, label="Distribution English")
    plt.plot(list(string.ascii_lowercase), dist_2, label="Distribution Text")
    plt.xlabel('Letters')
    plt.ylabel('Frequency (percentage)')
    plt.title(title)
    plt.legend()
    plt.show()

occurance_english = {
    'a': 8.2389258,    'b': 1.5051398,    'c': 2.8065007,    'd': 4.2904556,
    'e': 12.813865,    'f': 2.2476217,    'g': 2.0327458,    'h': 6.1476691,
    'i': 6.1476691,    'j': 0.1543474,    'k': 0.7787989,    'l': 4.0604477,
    'm': 2.4271893,    'n': 6.8084376,    'o': 7.5731132,    'p': 1.9459884,
    'q': 0.0958366,    'r': 6.0397268,    's': 6.3827211,    't': 9.1357551,
    'u': 2.7822893,    'v': 0.9866131,    'w': 2.3807842,    'x': 0.1513210,
    'y': 1.9913847,    'z': 0.0746517
}

dist_english = list(occurance_english.values())

def compute_fitting_quotient(text: bytes, plot=False, title=None) -> float:
    counter = Counter(text)
    dist_text = [
        (counter.get(ord(ch), 0) * 100) / len(text)
        for ch in occurance_english
    ]

    if plot:
        plot_linears(dist_english, dist_text, title=title)

    return sum([abs(a - b) for a, b in zip(dist_english, dist_text)]) / len(dist_text)

def decipher_single_byte(text: bytes, plot=False) -> Tuple[bytes, int]:

    original_text, encryption_key, min_fq = None, None, None
    for k in range(256):
        _text = single_byte_xor(text, k)
        _fq = compute_fitting_quotient(_text, plot=plot, title=f"Key: {k}")
        
        if min_fq is None or _fq < min_fq:
            encryption_key, original_text, min_fq = k, _text, _fq

    return original_text, encryption_key

def hamming_distance_bytes(text1: bytes, text2: bytes) -> int:
    dist = 0
    for byte1, byte2 in zip(text1, text2):
        dist += bin(byte1 ^ byte2).count('1')
    return dist

def hamming_score_bytes(text1: bytes, text2: bytes) -> float:
    return hamming_distance_bytes(text1, text2) / (8 * min(len(text1), len(text2)))

keys = []
group = []
for i in range(len(dat)):
    if hamming_score_bytes(bytes([dat[0]]), bytes([dat[i]])) < 0.3:
        group.append(i)

text = bytes([dat[x] for x in group])
original_text, encryption_key = decipher_single_byte(text)
keys.append(encryption_key)
    # print(f"Encryption Key: {encryption_key}")
    # print("-" * 100)

print("Keys data:",len(set(keys)), list(set(keys)))