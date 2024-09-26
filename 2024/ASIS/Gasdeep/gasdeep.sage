#!/usr/bin/env sage

from Crypto.Util.number import *
from secret import params, flag

def h(a):
	if a == 0:
		return 0
	else:
		g = F.gen()
		for _ in range(256):
			if g ** _ == a:
				return _

def H(M):
	assert M.nrows() == M.ncols()
	k, _H = M.nrows(), []
	for i in range(k):
		for j in range(k):
			_h = h(M[i, j])
			_H.append(bin(_h)[2:].zfill(8))
	return ''.join(_H)

def M2i(M):
	_H = H(M)
	return int(_H, 2)

def random_oracle(M):
	assert M.nrows() == M.ncols()
	k = M.nrows()
	try:
		r = M.order()
	except:
		r = k
	return H(M ** r)

def XOR(_H, _K):
	assert len(_H) == len(_K)
	X = [str(int(_h) ^^ int(_k)) for _h, _k in zip(_H, _K)]
	return ''.join(X)

def makey(params):
	u, k, d = params
	A, B = [random_matrix(F, k) for _ in '01']
	while True:
		f = PolynomialRing(F, 'x').random_element(degree = d)
		if f % A.characteristic_polynomial() != 0:
			break
	m, n = [randint(2, u) for _ in '01']
	R = f(A) ** m * B * f(A) ** n
	pkey = (A, B, R)
	skey = (f, m, n)
	return(pkey, skey)

def encrypt(pkey, msg):
	A, B, R = pkey
	k = A.nrows()
	_m = bytes_to_long(msg)
	_m = bin(_m)[2:]
	assert len(_m) <= 8 * k**2
	_M = _m.zfill(8 * k**2)
	while True:
		h = PolynomialRing(F, 'x').random_element(degree = d)
		if h % A.characteristic_polynomial() != 0:
			break
	m, n = [randint(2, u) for _ in '01']
	C, S = [h(A) ** m * _ * h(A) ** n for _ in [B, R]]
	D = XOR(random_oracle(S), _M)
	return(C, D) 

global F, d
F = GF(256)

u, k, d = params
assert u <= 1 << 64
pkey, _ = makey(params)
A, B, R = pkey

enc = encrypt(pkey, flag)
C, D = enc

print(f'g = {F.polynomial()}')
print(f'A = {M2i(A)}')
print(f'B = {M2i(B)}')
print(f'R = {M2i(R)}')
print(f'C = {M2i(C)}')
print(f'D = {int(D, 2)}')