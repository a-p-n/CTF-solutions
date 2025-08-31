from Anemoi_primitive.anemoi import *
from copy import deepcopy

from random import randint


# SPONGE
class SPONGE:
    def __init__(self, prime):
        self.prime = prime
        self.n_bits_per_block = len(bin(prime)[2:]) - 1
        # Anemoi params
        self.l = 1
        self.alpha = 3
        self.n_rounds = 21

    def hash(self, message, initial_c):
        assert initial_c < self.prime
        # ABSORBING PHASE
        state = [[0], [initial_c]]
        for b in message:
            state[0][0] = (state[0][0] + b) % self.prime
            temp = deepcopy(state)
            permutation = ANEMOI(self.prime, self.alpha, self.n_rounds, self.l)
            state = permutation(temp[0], temp[1])
        return state[0][0]



### Example (with incorrect value). See challenge.txt for the correct value.

prime = 275278823229291479988844812190164635993
message = [ 464353423421445, 3498282984334, 23849834832532, 2349835982348]
initial_c = 48382828582

S = SPONGE(prime)
target_hash = S.hash(message, initial_c)