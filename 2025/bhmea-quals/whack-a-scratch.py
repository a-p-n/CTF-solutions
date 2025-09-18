#!/usr/bin/env python3
#
# BlackHat MEA CTF 2025 Qualifiers :: Whack-A-Scratch
#
#

# Documentation imports
from __future__ import annotations
from typing import Tuple, List, Dict, NewType, Union

# Native imports
import os
import hashlib
from secrets import randbelow

# External dependencies
# None

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{D3BUGG1NG_1S_FUN}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Helper functions
def Inv(x: int, n: int) -> int:
    """ Returns multiplicative inverse of x modulo n. """
    assert x
    def Euclid(a: int, b: int) -> int:
        if a == 0:
            return 0, 1
        s1, t1 = Euclid(b % a, a)
        s = t1 - (b // a) * s1
        t = s1
        return s, t
    return Euclid(x % n, n)[0] % n

def DiagonalMatrix(entries: List[int], mod: int) -> List[List[int]]:
    """ Returns a matrix with diagonal entries modulo mod. """
    dim = len(entries)
    return [[0]*i + [entries[i] % mod] + [0]*(dim - i - 1) for i in range(dim)]

def RandomMatrix(dimensions: Tuple[int, int], mod: int) -> List[List[int]]:
    """ Returns a matrix with random entries modulo mod. """
    nrows, ncols = dimensions
    return [[randbelow(mod) for _i in range(ncols)] for _j in range(nrows)]

def InverseMatrix(matrix: List[List[int]], mod: int) -> List[List[int]]:
    """ Returns the inverse of a matrix modulo mod. """
    dim = len(matrix)
    assert all(len(i) == dim for i in matrix)
    amat = [[i for i in j] for j in matrix]
    imat = DiagonalMatrix([1]*dim, mod)
    for fd in range(dim):
        fdScalar = Inv(amat[fd][fd], mod)
        for j in range(dim):
            amat[fd][j] *= fdScalar
            amat[fd][j] %= mod
            imat[fd][j] *= fdScalar
            imat[fd][j] %= mod
        for i in list(range(dim))[:fd] + list(range(dim))[fd+1:]:
            crScalar = amat[i][fd]
            for j in range(dim):
                amat[i][j] = (amat[i][j] - crScalar * amat[fd][j]) % mod
                imat[i][j] = (imat[i][j] - crScalar * imat[fd][j]) % mod
    return imat

def ProductMatrix(matrixLeft: List[List[int]], matrixRight: List[List[int]], mod: int) -> List[List[int]]:
    """ Returns the product of two matrices modulo mod. """
    assert len(matrixLeft[0]) == len(matrixRight)
    lmat = [[i for i in j] for j in matrixLeft]
    rmat = [[i for i in j] for j in matrixRight]
    pmat = [[0] * len(matrixRight[0]) for _ in range(len(matrixLeft))]
    for i in range(len(matrixLeft)):
        for j in range(len(matrixRight[0])):
            pmat[i][j] = sum([x * y for x,y in zip(lmat[i], [k[j] for k in rmat])]) % mod
    return pmat

def PowerMatrix(matrix: List[List[int]], power: int, mod: int) -> List[List[int]]:
    """ Returns the power of a matrix modulo mod. """
    dim = len(matrix)
    assert all(len(i) == dim for i in matrix)
    rmat = DiagonalMatrix([1]*dim, mod)
    smat = [[i for i in j] for j in matrix]
    while power:
        if power & 1:
            rmat = ProductMatrix(rmat, smat, mod)
        smat = ProductMatrix(smat, smat, mod)
        power >>= 1
    return rmat


# Challenge class
class WhackAScratch:
    """ Gamba with a built-in frustration outlet. """

    # Class constructors

    def __init__(self, masterKey: bytes, rotateRate: int = 12) -> None:
        secBits = NUM_MAT * MAT_DIM * INT_MOD.bit_length()
        assert len(masterKey) * 8 >= secBits
        key = int.from_bytes(masterKey, 'big') & (2 ** secBits - 1)
        self.key = key.to_bytes(-(-secBits // 8), 'big')
        keyPieces = []
        while len(keyPieces) < NUM_MAT * MAT_DIM:
            keyPieces.append(key & (2 ** INT_MOD.bit_length() - 1))
            key >>= INT_MOD.bit_length()
        self.static = self.__GenInner(keyPieces)
        self.ephemeral = None
        self.cashbox = int.from_bytes(FLAG, 'big')
        self.limit = rotateRate
        self.i = rotateRate

    # Private methods

    def __GenInner(self, keyPieces: List[int]) -> Tuple[List[List[int]]]:
        """ Generates inner matrices for a private key. """
        pieceLen = len(keyPieces) // NUM_MAT
        diagMats = [DiagonalMatrix(keyPieces[i*pieceLen:(i+1)*pieceLen], INT_MOD) for i in range(NUM_MAT)]
        for k in range(NUM_MAT):
            for j in range(MAT_DIM):
                for i in range(j + 1, MAT_DIM):
                    if k & 1:
                        diagMats[k][j][i] = randbelow(INT_MOD)
                    else:
                        diagMats[k][i][j] = randbelow(INT_MOD)
        return diagMats
    
    def __GenOuter(self) -> Tuple[List[List[int]]]:
        """ Generates outer matrices for a private key. """
        idMat = DiagonalMatrix([1]*MAT_DIM, INT_MOD)
        while True:
            A = RandomMatrix((MAT_DIM, MAT_DIM), INT_MOD)
            if ProductMatrix(A, InverseMatrix(A, INT_MOD), INT_MOD) == idMat:
                break
        while True:
            B = RandomMatrix((MAT_DIM, MAT_DIM), INT_MOD)
            if ProductMatrix(B, InverseMatrix(B, INT_MOD), INT_MOD) == idMat:
                break
        return A, B
    
    def __RotateEphemeral(self) -> None:
        """ Generates a new ephemeral private key. """
        A, B = self.__GenOuter()
        pows = [randbelow(INT_MOD) for _ in range(NUM_MAT)]
        C = [[i for i in j] for j in A]
        for i in range(NUM_MAT):
            C = ProductMatrix(C, PowerMatrix(self.static[i], pows[i], INT_MOD), INT_MOD)
        C = ProductMatrix(C, B, INT_MOD)
        self.ephemeral = {'A': A, 'B': B, 'C': C}
        while True:
            self.j = randbelow(2 ** (2 * MAT_DIM))
            if bin(self.j).count('1') == MAT_DIM:
                break
        self.i = 0

    # Public methods

    def Whack(self, ijk: Tuple[int, int, int]) -> None:
        """ Whack the ticket machine to vent some frustration. """
        i, j, k = ijk
        self.static[i][j][k] += 1
        if self.static[i][j][k] >= INT_MOD:
            raise ValueError('YOU BROKE MY TICKET MACHINE?!')
        
    def Scratch(self, num: int) -> List[int]:
        """ Hic sunt gamba. """
        self.cashbox += num * TICKET_COST
        ticket = []
        for _ in range(num):
            if self.i >= self.limit:
                self.__RotateEphemeral()
            kLeft = RandomMatrix((1, MAT_DIM), INT_MOD)
            kRight = [[i] for i in kLeft[0]]
            R = ProductMatrix(InverseMatrix(self.ephemeral['A'], INT_MOD), kRight, INT_MOD)
            S = ProductMatrix(kLeft, InverseMatrix(self.ephemeral['B'], INT_MOD), INT_MOD)
            if self.j & 1:
                T = ProductMatrix(ProductMatrix(self.ephemeral['C'], self.ephemeral['A'], INT_MOD), kRight, INT_MOD)
            else:
                T = ProductMatrix(ProductMatrix(self.ephemeral['C'], self.ephemeral['B'], INT_MOD), kRight, INT_MOD)
            self.i += 1
            self.j >>= 1
            ticket.append([i[0] for i in R] + S[0] + [i[0] for i in T])
        return ticket
    
    def OpenCashBox(self, key: bytes) -> int:
        """ This is one way to recoup your losses, I suppose... """
        if key == self.key:
            cash = self.cashbox
            self.cashbox = 0
            return cash
        return -1


# Main loop
if __name__ == "__main__":

    # Challenge parameters
    INT_MOD = 2**21 - 9
    MAT_DIM = 6
    NUM_MAT = 2
    TICKET_COST = 189
    START_CREDS = 2 ** (NUM_MAT * MAT_DIM)


    # Challenge setup
    KEY = hashlib.sha256(b"Whack-A-Scratch::" + FLAG).digest()
    WAS = WhackAScratch(KEY)

    userCredits = START_CREDS

    HDR = r"""|
|                          __      __
|                         /  \    /  \
|                         \   \/\/   /
|                          \        /
|                           \__/\  /
|                           |  |_\/
|                           |  |  \
|      _________            |   Y  \__          __     
|     /   _____/ ___________|___| _/  |_  ____ |  |__  
|     \_____  \_/ ___\_  __ \__  \\   __\/ ___\|  |  \ 
|     /        \  \___|  | \// __ \|  | \  \___|   Y  \
|    /_______  /\___  >__|  (____  /__|  \___  >___|  /
|            \/     \/     _/ ___\/          \/     \/ 
|                          \  \___
|                           \___  >
|                            |  \/__
|                            |  |/ /
|                            |    <
|                            |__|_ \
|                                 \/
|
|  [~] Welcome to Whack-A-Scratch. Remember to WHACK and SCRATCH responsibly!"""
    print(HDR)


    # Main loop
    userOptions = ['Whack', 'Scratch', 'Open Cash Box']
    TUI = "|\n|  Menu ({} credits):\n|    " + "\n|    ".join('[' + i[0] + ']' + i[1:] for i in userOptions) + "\n|    [Q]uit\n|"

    while True:
        try:

            print(TUI.format(userCredits))
            choice = input('|  > ').lower()

            # [Q]uit
            if choice == 'q':
                print("|\n|  [~] Goodbye ~ !\n|")
                break

            # [W]hack
            elif choice == 'w':
                print("|\n|  [?] What part of the ticket machine will feel your wrath?")
                userInput = input('|  (int[3]) > ')

                ijk = userInput.split(' ') if ' ' in userInput else userInput.split(',')
                ijk = [int(i.strip('()[], ')) for i in ijk]
                WAS.Whack(ijk)

                print("|\n|  [~] *you whacked the ticket machine*")

            # [S]cratch
            elif choice == 's':
                print("|\n|  [?] How many tickets would you like? They cost {} credits a piece.".format(TICKET_COST))
                userInput = input('|  > (int) ')

                num = int(userInput)
                cost = num * TICKET_COST
                if cost > userCredits:
                    raise ValueError('You are going to need more credits...')
                userCredits -= cost

                ticket = WAS.Scratch(int(userInput))
                print("|\n|  [~] *ticket machine go brrrrr*")
                print('\n'.join(['|    [' + ', '.join('{:7d}'.format(j) for j in i) + ']' for i in ticket]))

                winnings = sum([sum([bin(i).count('1') for i in j]) for j in ticket])
                userCredits += winnings
                if winnings < cost:
                    print("|\n|  [~] Oof, you lost {} credits on that one...".format(cost - winnings))
                else:
                    print("|\n|  [~] Sweet, you are up {} credits with that one!".format(winnings - cost))

            # [O]pen Cash Box
            elif choice == 'o':
                print("|\n|  [?] The cash box requires a key, obviously...")
                userInput = input('|  > (hex) ')

                cash = WAS.OpenCashBox(bytes.fromhex(userInput))
                if cash < 0:
                    print("|\n|  [~] That key did not seem to fit...")
                else:
                    print("|\n|  [~] You retrieve {} credits.".format(cash))

            else:
                print("|\n|  [!] Invalid choice.")

        except KeyboardInterrupt:
            print("\n|\n|  [~] Goodbye ~ !\n|")
            break

        except Exception as e:
            print('|\n|  [!] {}'.format(e))