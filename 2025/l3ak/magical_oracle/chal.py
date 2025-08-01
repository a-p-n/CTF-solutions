#!/usr/bin/env python3
# Author: supasuge | https://github.com/supasuge
# Difficulty: Medium
import sys
import os
import time
import signal
import random
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
from secrets import randbelow

PRIME_BITS       = 256
SESSION_TIMEOUT  = int(os.getenv('TIMEOUT', 60))

def timeout_handler(signum, frame):
    print("\n⏰ Session timeout! The Magical Oracle retreats.")
    sys.exit(1)

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(SESSION_TIMEOUT)

class MagicalOracle:
    def __init__(self, connection_id=None):
        self.p = getPrime(PRIME_BITS)
        self.n = self.p.bit_length()
        self.k = int(self.n**0.5) + self.n.bit_length() + 1
        self.d = 2 * int(self.n**0.5) + 3
        self.alpha = randbelow(self.p - 1) + 1

        self.queries_used = 0
        self.max_queries  = self.d
        self.start_time   = time.time()
        self.solved       = False

    def _msb_oracle(self, x):
        threshold = self.p >> (self.k + 1) 
        time.sleep(0.05)
        for _ in range(1000):
            z = random.randrange(1, self.p)
            if abs(x - z) < threshold:
                return z
        
        return (x + random.randint(-threshold//2, threshold//2)) % self.p

    def banner(self):
        return f"""
╔{'═'*65}╗
║              🧙‍♂️ Welcome to the Magical Oracle! 🧙‍♀️              ║
╟{'─'*65}╢
║  Prime (p): {self.p:<52}║
║  Bit length (n): {self.n:<49}║
║  MSB leak (k): {self.k:<50}║
║  Max queries: {self.max_queries:<48}║
║  Timeout: {SESSION_TIMEOUT}s{' '*(44-len(str(SESSION_TIMEOUT)))}║
╚{'═'*65}╝
"""

    def menu(self):
        rem = max(0, SESSION_TIMEOUT - int(time.time() - self.start_time))
        return f"""
📋 Magical Oracle — time remaining: {rem}s
Queries used: {self.queries_used}/{self.max_queries}

1) Query MSB oracle
2) Show encrypted data
3) Show parameters
4) Get a hint
5) Exit

Choose option: """

    def query(self):
        if self.queries_used >= self.max_queries:
            return "❌ No queries left!"
        t = random.randrange(1, self.p)
        leak = self._msb_oracle((self.alpha * t) % self.p)
        self.queries_used += 1
        return f"Oracle #{self.queries_used}: t={t}, z={leak}"

    def encrypt_flag(self):
        raw = open('flag.txt','rb').read().strip()
        key = hashlib.sha256(str(self.alpha).encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC)
        ct = cipher.iv + cipher.encrypt(pad(raw, AES.block_size))
        return base64.b64encode(ct).decode()

    def show_encrypted(self):
        blob = self.encrypt_flag()
        return f"Flag: {blob}"

    def show_params(self):
        return (f"Prime p = {self.p}\n"
                f"Bit length n = {self.n}\n"
                f"MSB leak k = {self.k}\n"
                f"Max queries d = {self.max_queries}\n"
                f"Queries used = {self.queries_used}\n")

    def hint(self):
        tips = [
            "Use magic, bro...",
            "I just work here"
        ]
        return "💡 Hint: " + tips[min(self.queries_used//3, len(tips)-1)]

if __name__ == '__main__':
    oracle = MagicalOracle()
    print(oracle.banner())
    while True:
        try:
            choice = input(oracle.menu()).strip()
        except KeyboardInterrupt:
            print("\n👋 Bye-bye!")
            break
        if choice == '1':
            print(oracle.query(), flush=True)
        elif choice == '2':
            print(oracle.show_encrypted(), flush=True)
        elif choice == '3':
            print(oracle.show_params(), flush=True)
        elif choice == '4':
            print(oracle.hint(), flush=True)
        elif choice == '5':
            print("👋 Oracle fading away...")
            sys.stdout.flush()
            break
        else:
            print("❌ Choose 1–5, mortal!")
            sys.stdout.flush()
            sys.exit(1)