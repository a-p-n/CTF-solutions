#!/usr/bin/env sage

import sys
from Crypto.Util.number import *
from hashlib import sha512
from flag import flag

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc():
	return sys.stdin.buffer.readline()

def sign(msg, skey):
	global k
	h = bytes_to_long(sha512(msg).digest())
	k = toffee(u, v, k)
	P = k * G
	r = int(P.xy()[0]) % _n
	s = inverse(k, _n) * (h + r * skey) % _n
	return (r, s)

def toffee(u, v, k):
	return (u * k + v) % _n

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".:::    Welcome to the Toffee chocolate cryptography task!    ::.", border)
	pr(border, ".:  Your mission is to find flag by analyzing the signatures!  :.", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	global flag, u, v, k, _n, G
	skey = bytes_to_long(flag)
	p = 0xaeaf714c13bfbff63dd6c4f07dd366674ebe93f6ec6ea51ac8584d9982c41882ebea6f6e7b0e959d2c36ba5e27705daffacd9a49b39d5beedc74976b30a260c9
	a, b = -7, 0xd3f1356a42265cb4aec98a80b713fb724f44e747fe73d907bdc598557e0d96c5
	_n = 0xaeaf714c13bfbff63dd6c4f07dd366674ebe93f6ec6ea51ac8584d9982c41881d942f0dddae61b0641e2a2cf144534c42bf8a9c3cb7bdc2a4392fcb2cc01ef87
	x = 0xa0e29c8968e02582d98219ce07dd043270b27e06568cb309131701b3b61c5c374d0dda5ad341baa9d533c17c8a8227df3f7e613447f01e17abbc2645fe5465b0
	y = 0x5ee57d33874773dd18f22f9a81b615976a9687222c392801ed9ad96aa6ed364e973edda16c6a3b64760ca74390bb44088bf7156595f5b39bfee3c5cef31c45e1
	F = FiniteField(p)
	E = EllipticCurve(F, [a, b])
	G = E(x, y)
	u, v, k = [randint(1, _n) for _ in ';-)']
	while True:
		pr(f"{border} Options: \n{border}\t[G]et toffee! \n{border}\t[S]ign message! \n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'g':
			pr(border, f'Please let me know your seed: ')
			_k = sc().decode().strip()
			try:
				_k = int(_k)
			except:
				die(border, 'Your seed is not valid! Bye!!')
			pr(f'{toffee(u, v, _k) = }')
		elif ans == 's':
			pr(border, f'Please send your message: ')
			msg = sc().strip()
			r, s = sign(msg, skey)
			pr(border, f'{r = }')
			pr(border, f'{s = }')
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()