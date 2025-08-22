from ecc import G, ecc_mul, q
from random import randrange
from secret import flag

ROUNDS = 1000
THRESHOLD = 950
score = 0

print("Welcome!. Let's see if you play the odds... or you play the man.")
print("How sharp are you with partial DLPs?")
print(f"Score at least {THRESHOLD} points out of {ROUNDS} to win BIG")
print()

for i in range(1, ROUNDS + 1):
    try:
        print(f"Round {i}")
        k = randrange(1, q)
        R = ecc_mul(G, k)
        print(f"{R = }")
        ans = int(input("Is k even (0) or odd(1)?????? > "))
        score += (k % 2) == ans
    except ValueError:
        print("Womp womp. Try entering 0 or 1, dude")
    except Exception:
        print("Something went wrong. Moving on...")

print()
if score >= THRESHOLD:
    print(f"Impressive, very nice! You nailed {score}/{ROUNDS}.")
    print(f"Here's your reward: {flag}")
else:
    print(f"You got {score}/{ROUNDS}. Better luck next time...")
    print("95% of cryptographers quit before hitting it big")
