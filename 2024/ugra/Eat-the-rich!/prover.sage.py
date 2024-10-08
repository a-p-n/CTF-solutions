

# This file was *autogenerated* from the file prover.sage
from sage.all_cmdline import *   # import sage library

_sage_const_16 = Integer(16); _sage_const_0 = Integer(0); _sage_const_2 = Integer(2); _sage_const_32 = Integer(32); _sage_const_16384 = Integer(16384); _sage_const_8 = Integer(8); _sage_const_1 = Integer(1)
import gmpy2
import json
import random
import requests
import time


BASE = "https://securityisamyth.q.2024.ugractf.ru"
TOKEN = "u2w0l5qd2v0lxzyz"

p, g, y = [int(n, _sage_const_16 ) for n in requests.post(f"{BASE}/{TOKEN}/get-parameters").text.split(", ")]

print("Computing, please wait...")
rs = [random.randint(_sage_const_0 , p - _sage_const_2 ) for _ in range(_sage_const_32 )]
cs = [int(gmpy2.powmod(g, r, p)) for r in rs]

choices = eval(requests.post(f"{BASE}/{TOKEN}/announce-cs", data=b"".join(c.to_bytes(_sage_const_16384  // _sage_const_8 , "big") for c in cs)).text)

x = eval(input(f"Please solve {g:x}^x = 0x{y:x} (mod 0x{p:x}) for x: "))
print("Verifying...")
answers = [(x + r) % (p - _sage_const_1 ) if choice == _sage_const_0  else r for r, choice in zip(rs, choices)]
result = requests.post(f"{BASE}/{TOKEN}/answer-choices", data=b"".join(int(answer).to_bytes(_sage_const_16384  // _sage_const_8 , "big") for answer in answers)).text
print(result)

