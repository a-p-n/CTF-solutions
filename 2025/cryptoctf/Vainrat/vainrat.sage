#!/usr/bin/env sage

import sys
from Crypto.Util.number import *
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

nbit = 110
prec = 4 * nbit
R = RealField(prec)

def rat(x, y):
	x = R(x + y) * R(0.5)
	y = R((x * y) ** 0.5)
	return x, y

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".::               Welcome to Vain Rat challenge!              ::. ", border)
	pr(border, " You should chase the vain rat and catch it to obtain the flag!   ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	m = bytes_to_long(flag)
	x0 = R(10 ** (-len(str(m))) * m)
	while True:
		y0 = abs(R.random_element())
		if y0 > x0: break
	assert len(str(x0)) == len(str(y0))
	c = 0
	pr(border, f'We know y0 = {y0}')
	while True:
		pr("| Options: \n|\t[C]atch the rat \n|\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'c':
			x, y = rat(x0, y0)
			x0, y0 = x, y
			c += 1
			if c <= randint(12, 19):
				pr(border, f'Unfortunately, the rat got away :-(')
			else: pr(border, f'y = {y}')
		elif ans == 'q': die(border, "Quitting...")
		else: die(border, "Bye...")

if __name__ == '__main__':
	main()