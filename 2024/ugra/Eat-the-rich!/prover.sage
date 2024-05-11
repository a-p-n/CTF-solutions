import gmpy2
import json
import random
import requests
import time
from mt19937predictor import MT19937Predictor
predictor = MT19937Predictor()


BASE = "https://securityisamyth.q.2024.ugractf.ru"
# TOKEN = input("Enter token: ")
TOKEN = 'u2w0l5qd2v0lxzyz'


p, g, y = [int(n, 16) for n in requests.post(
    f"{BASE}/{TOKEN}/get-parameters").text.split(", ")]
# print(f"p = 0x{p:x}, g = 0x{g:x}, y = 0x{y:x}")

predictor.setrandbits(g, 16384)
predictor.setrandbits(y, 16384)
ch = predictor.getrandbits(32)
guess = [(ch >> i) & 1 for i in range(32)]
inv_y = pow(y, -1, p)
# print(guess)

print("Computing, please wait...")
rs = [random.randint(0, p - 2) for _ in range(32)]
cs = [int(gmpy2.powmod(g, r, p)) if pos ==
      1 else inv_y for r, pos in zip(rs, guess)]

choices = eval(requests.post(f"{BASE}/{TOKEN}/announce-cs",
               data=b"".join(c.to_bytes(16384 // 8, 'big') for c in cs)).text)

assert choices == guess, "Choices are not correct"

# x = eval(input(f"Please solve {g:x}^x = 0x{y:x} (mod 0x{p:x}) for x: "))
# print("Verifying...")

answers = [0 if choice == 0 else r for r, choice in zip(rs, choices)]
result = requests.post(f"{BASE}/{TOKEN}/answer-choices", data=b"".join(
    answer.to_bytes(16384 // 8, 'big') for answer in answers)).text
print(result)
