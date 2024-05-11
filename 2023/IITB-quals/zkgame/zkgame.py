import statistics
import random
import sys
from secret import FLAG

MIN = 0
MAX = 1000
NUM_PARTIES = 50
STD_DEV = 10
PRIVATE_INPUTS = []

def init_vars():
    def are_all_distinct(lst):
        return len(lst) == len(set(lst))
    
    global PRIVATE_INPUTS
    PRIVATE_INPUTS = [random.randint(MIN, MAX) for _ in range(NUM_PARTIES)]
    if not are_all_distinct(PRIVATE_INPUTS):
        init_vars()


def generate_transcript():
    shares = [set() for _ in range(NUM_PARTIES)]
    for sender_party_idx in range(NUM_PARTIES):
        cumsum = 0
        for receiver_party_idx in range(NUM_PARTIES):
            if sender_party_idx == receiver_party_idx:
                continue
            share = statistics.NormalDist(PRIVATE_INPUTS[sender_party_idx], STD_DEV).samples(1)[0]
            shares[receiver_party_idx].add(share)
            cumsum += share
        shares[sender_party_idx].add(PRIVATE_INPUTS[sender_party_idx] - cumsum)
    total_sum = round(sum(map(sum, shares)))

    print("Transcript:")
    for party_idx in range(NUM_PARTIES):
        print(f"Party {party_idx + 1}: {shares[party_idx]}")
    print(f"Total sum: {total_sum}")
        

def submit_private_inputs():
    print("Enter the private inputs (space-separated ordered list): ", end='')
    try:
        submitted_inputs = list(map(int, input().strip().split(' ')))
        if submitted_inputs == PRIVATE_INPUTS:
            print("You have more knowledge than zero knowledge? Let me give you the knowledge you desire:")
            print(FLAG)
            sys.exit(0)
        else:
            print("You have no knowledge? Bye!")
            sys.exit(0)
    except ValueError:
        print("You don't even know how to enter numbers? Bye!")
        sys.exit(0)


if __name__ == "__main__":
    print("Welcome to the ZK-SUM game!")
    init_vars()

    while True:
        print("\nMake a choice:")
        print("1) Get a transcript")
        print("2) Submit the private inputs\n")
      
        print("Enter your choice: ", end='')
        try:
            choice = int(input())
            if choice == 1:
                generate_transcript()
            elif choice == 2:
                submit_private_inputs()
            else:
                print("Invalid choice. Bye!")
                sys.exit(0)
        except ValueError:
            print("You don't even know how to enter a number? Bye!")
            sys.exit(0)