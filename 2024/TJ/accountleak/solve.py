from pwn import *
import math
from Cryptodome.Util.number import long_to_bytes

context.log_level = 'debug'
host = 'tjc.tf'
port = 31601
conn = remote(host, port)
def extract_values(data):
    if isinstance(data, bytes):
        data_str = data.decode('utf-8')
    else:
        data_str = data
    lines = data_str.split('\n')

    num_lines = []
    
    for line in lines:
        if '<Bobby>' in line and 'numbers' in line:
            part = line.split('numbers,')[1]
            nums = part.split('and')
            num_lines.extend([num.strip() for num in nums])
    c = int(num_lines[0])
    n = int(num_lines[1])
    return c, n
data = conn.recvuntil(b"<You> ").decode()
print(f"Initial data: {data}")
c, n = extract_values(data)
print(f"Extracted c: {c}, n: {n}")
conn.sendline("yea")
data = conn.recvuntil(b"<You> ").decode()
print(f"Response after 'yea': {data}")
dont_leak_this = None
lines = data.split('\n')
for line in lines:
    if "<Bobby> " in line and "oop wasnt supposed to copypaste that" not in line and "you cant crack my account tho >:)" not in line:
        try:
            dont_leak_this = int(line.split('<Bobby> ')[1].strip())
            break
        except ValueError:
            continue

if dont_leak_this is None:
    raise ValueError("Failed to extract dont_leak_this value")

print(f"Extracted dont_leak_this: {dont_leak_this}")
sub = None
p = None
q = None

for sub in range(1, 1 << 20):  
    try:
        p_plus_q_est = (n - dont_leak_this + sub**2) // sub
        a = 1
        b = -p_plus_q_est
        c_val = n

        discriminant = b * b - 4 * a * c_val
        if discriminant < 0:
            continue

        sqrt_discriminant = int(math.isqrt(discriminant))
        if sqrt_discriminant * sqrt_discriminant != discriminant:
            continue

        p = (p_plus_q_est + sqrt_discriminant) // 2
        q = (p_plus_q_est - sqrt_discriminant) // 2
        if p * q == n:
            break
    except ZeroDivisionError:
        continue

print(f"Found primes p: {p}, q: {q}")
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)

# Decrypt the password
my_password = pow(c, d, n)
print(f"Decrypted password (integer): {my_password}")
# Convert my_password to a string
password_str = str(my_password)
print(f"Decrypted password (string): {password_str}")
conn.sendline(password_str)
final_response = conn.recvall().decode()
print(f"Final response: {final_response}")
conn.close()