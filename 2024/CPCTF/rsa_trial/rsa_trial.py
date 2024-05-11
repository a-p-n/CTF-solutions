from Crypto.Util.number import getPrime, bytes_to_long

flag = "CPCTF{Fake_flag}"

p = getPrime(1024)
q = getPrime(1024)
hint = p ** 3 + q ** 3

n = p * q
e = 0x10001
c = pow(bytes_to_long(flag.encode()), e, n)

with open("output.py", "w") as f:
    f.write(f"e = {e}\n")
    f.write(f"n = {n}\n")
    f.write(f"c = {c}\n")
    f.write(f"hint = {hint}\n")