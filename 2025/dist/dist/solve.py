from z3 import *

with open("output.txt", "r") as f:
    lines = f.readlines()
    for line in lines:
        if line.startswith("Here is your encrypted message:"):
            cipher = bytes.fromhex(lines[lines.index(line)+1])
            print(cipher.hex())
        elif line.startswith("Here is your hint:"):
            hints = [int(x) for x in lines[lines.index(line)+1:]]
    


def solve(S_vals, M):

    x = BitVec('x', 256)
    M = BitVecVal(M, 256)

    s = Solver()

    for i in range(1):
        S_i = BitVecVal(S_vals[i], 256)
        S_next = BitVecVal(S_vals[i + 1], 256)
        s.add(URem(S_i ^ x, M) == S_next)

    if s.check() == sat:
        model = s.model()
        return model[x].as_long()
    else:
        return None

M = 83562276251485261123727537064795747478963486280022872567182007816794512863148

