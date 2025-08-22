from mersenne import *
from Crypto.Util.number import long_to_bytes

byte_array = []

with open('gpl-3.0.txt', 'rb') as f_1:
    with open('gpl-3.0_encrypted.bin', 'rb') as f_2:
        while bits1:=f_1.read(4):
            bits2 = f_2.read(4)
        
            byte_array.append(int.from_bytes(bits1)^int.from_bytes(bits2))

breaker = BreakerPy()
seed = breaker.get_seeds_python_fast(byte_array[:624])

n = 0
for val in seed[::-1]:
    n = n<<32
    n += val

print(n)
print(long_to_bytes(n))