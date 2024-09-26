#!/usr/bin/env python3

import time
from functools import wraps
from Crypto.Util.number import *
from signal import *
from secret import rapid_factoreal_check, flag

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc():
	return sys.stdin.buffer.readline()

class TimeoutError(Exception):
	pass

def exec_limit(mt):
	def decorator(func):
		@wraps(func)
		def wrapper(*args, **kwargs):
			def _handle_timeout(signum, frame):
				raise TimeoutError(f"Function execution time exceeded {mt} seconds.")
			old_handler = signal(SIGALRM, _handle_timeout)
			alarm(int(mt))
			try:
				result = func(*args, **kwargs)
			except TimeoutError:
				return False
			finally:
				signal(SIGALRM, old_handler)
			return result
		return wrapper
	return decorator

TIMEOUT = 3
@exec_limit(TIMEOUT)
def factoreal(n, k, b):
	if b: # When YOU have access to supercomputer!
		i, s = 1, 1
		while i < n + 1:
			s = (s * i) % k
			i += 1
		if (4 * s + n + 5) % k == 0:
			return True
		return False
	else: # Otherwise
		return rapid_factoreal_check(n)

def main():
	global secret, border
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, "Welcome to Clement Crypto Challenge, we have gained access to a   ", border)
	pr(border, "very powerful supercomputer with high processing capabilities. Try", border)
	pr(border, "to connect to the app running on this computer and find the flag. ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	b, c, nbit, STEP = False, 0, 64, 40
	for level in range(STEP):
		pr(border, f"Your are at level {level + 1} of {STEP}")
		pr(border, f"Please submit an {nbit}-integer:")
		_n = sc().decode()
		try:
			_n = int(_n)
			_k = _n**2 + 4*_n + 3
		except:
			die(border, 'Your input is not integer! Bye!!')
		if _n.bit_length() == nbit:
			try:
				_b = factoreal(_n, _k, b)
			except TimeoutError:
				pass
		else:
			die(border, f"Your input integer is NOT {nbit}-bit! Bye!!") 
		if _b:
			c += 1
			nbit = int(1.1 * nbit) + getRandomRange(1, 12)
			if c >= STEP:
				die(border, f'Congratulation! You got the flag: {flag}')
		else:
			die(border, "Wrong response! Start again. Bye!!") 

if __name__ == '__main__':
	main()