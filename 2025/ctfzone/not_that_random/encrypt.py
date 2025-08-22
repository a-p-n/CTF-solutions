import random
import argparse

parser = argparse.ArgumentParser(description='Strong encryptor')
parser.add_argument('--key', required=True)
args = parser.parse_args()

random.seed(args.key)
with open('gpl-3.0.txt', 'rb') as f_in:
    with open('gpl-3.0_encrypted.bin', 'wb') as f_out:
        while word := f_in.read(4):
            r = random.getrandbits(32)
            f_out.write((int.from_bytes(word) ^ r).to_bytes(4))
