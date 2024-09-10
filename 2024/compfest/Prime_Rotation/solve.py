from gmpy2 import iroot
exec(open('out.txt').read())

a = int(str(n)[:100] + str(n)[-100:]) # a = xz

rest = ((n - a) - (10**400*a)) // 10**100

b = int(str(rest)[:100] + str(rest)[-100:]) - 4*10**100 # b = xy + yz

c = (rest - b - (10**200 * b))//10**100

print(f'a = {a}')
print(f'b = {b}')
print(f'c = {c}')

print(iroot(c + 2*b + 2*a, 2))
d = iroot(c + 2*b + 2*a, 2)[0] # d = x + y + z

print(f'd = {d}')