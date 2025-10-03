import sys
import signal

assert((sys.version_info.major, sys.version_info.minor) == (3, 9))

signal.alarm(30)

FLAG = "crew{test flag please ignore}"

def dummy1(a):
  pass
def dummy2(a, b):
  pass
def dummy3(a, b, c):
  pass

dummies = [None, dummy1, dummy2, dummy3]

def create_function(parameters, prompt):
  bytecode = bytes.fromhex(input(prompt))
  
  if len(bytecode) > 512:
    print("Too long")
    exit()
  
  opcodes = [bytecode[i*2] + bytecode[i*2+1]*256 for i in range((len(bytecode)+1) // 2)]
  
  allowlist = [ 0x0001, 0x0004, 0x0006, 0x000f, 0x0017, 0x0190 ] + [0x0073 + i * 512 for i in range(128)]
  
  if any([op not in allowlist for op in opcodes]):
    print("Illegal opcode")
    exit()
  
  preamble = b"".join([bytes([0x7c, i]) for i in range(parameters)])
  
  code = preamble + bytecode + bytes([0x53, 0])
  
  dummy = dummies[parameters]
  
  dummy.__code__ = dummy.__code__.replace(co_code=code,co_stacksize=1000000000)
  
  return dummy

import secrets

subtract = create_function(2, "Enter a function which subtracts two numbers: ")

for i in range(10000):
  a = secrets.randbelow(2**32)
  b = secrets.randbelow(2**32)
  
  if subtract(a, b) != a - b:
    print("Nope")
    exit()

constant1337 = create_function(1, "Enter a function which always returns 1337: ")

for i in range(10000):
  if constant1337(secrets.randbelow(2**32)) != 1337:
    print("Nope")
    exit()

multiply = create_function(2, "Enter a function which multiplies two positive integers: ")

for i in range(10000):
  a = secrets.randbelow(255) + 1
  b = secrets.randbelow(255) + 1
  
  if multiply(a, b) != a * b:
    print("Nope")
    exit()

print(FLAG)
