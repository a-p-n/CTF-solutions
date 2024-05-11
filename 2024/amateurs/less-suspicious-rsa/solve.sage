n, e, c = map(eval, open('/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/amateurs/less-suspicious-rsa/output.txt').read().split())

F = Zmod(n)
P.<k> = PolynomialRing(F)
k = P.gen()

def factorial(n):
    if n == 0:
        return 1
    return factorial(n-1) * n

f = (k*factorial(90) + 1)
f = f.monic()

beta = 0.5
dd = f.degree()
epsilon = beta/7
XX = ceil(n**((beta**2/dd) - epsilon))

k = f.small_roots(XX, beta, epsilon)[0]
q = (k*factorial(90) + 1)
p = n//int(q)
print(p)
print(q)
assert p*q == n

d = inverse_mod(e, (p-1)*(q-1))
m = pow(c,d,n)
print(bytes.fromhex(hex(int(m))[2:]).decode())