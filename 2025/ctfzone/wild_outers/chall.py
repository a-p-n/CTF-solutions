from Crypto.Cipher import ChaCha20
from Crypto.Hash import BLAKE2b
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
from secret import flag

from ecc import G, cLadderS, o


def encrypt(
    data: bytes,
    S: tuple[int] = (
        0x113CCBD73B66E7534D1792202A3913821C416643AB2B8F63D4052A59A4FE96D72B8C9EEA98F05A,
        1,
    ),
):
    k = randrange(1, o)
    B, _ = cLadderS(S, k)
    E, _ = cLadderS(G, k)

    hasher = BLAKE2b.new(digest_bytes=32)
    hasher.update(f"{E[0]}:{E[1]}".encode())
    key = hasher.digest()
    nonce = get_random_bytes(12)
    cip = ChaCha20.new(key=key, nonce=nonce)
    ct = nonce + cip.encrypt(data)

    return ct, B


ct, B = encrypt(flag)

print(f"{ct=}")
print(f"{B=}")
