# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Helpers for handling dilithium structures.

Mostly translated by Gemini from the C reference code.
Gemini can make mistakes, so double-check if you encounter any bugs.

Example:

# Loading keys
rho, t1 = load_pk('../public/pk.bin')
A = load_pk_mat('../public/pk.mat')
s1, s2, t0 = load_sk('../private/sk.bin')

# Loading signatures
with open('../public/sig.bin', 'rb') as f:
  c, z, h = load_sig_stream(f)

# Serialize recovered secrets
s1bytes = b''.join([polyeta_pack(poly) for poly in s1_pred_all])
t0bytes = b''.join([polyt0_pack(poly) for poly in t0_pred])
"""

import hashlib

# Dilithium2 params
N = 256
SEEDBYTES = 32
CRHBYTES = 64
TRBYTES = 64
RNDBYTES = 32
N = 256
Q = 8380417
D = 13
ROOT_OF_UNITY = 1753
K = 4
L = 4
ETA = 2
TAU = 39
BETA = 78
GAMMA1 = 1 << 17
GAMMAy = GAMMA1 // 2
GAMMA2 = (Q - 1) // 88
OMEGA = 80
CTILDEBYTES = 32

POLYT1_PACKEDBYTES = 320
POLYT0_PACKEDBYTES = 416
POLYVECH_PACKEDBYTES = OMEGA + K
POLYZ_PACKEDBYTES = 576
POLYW1_PACKEDBYTES = 192
POLYETA_PACKEDBYTES = 96

CRYPTO_PUBLICKEYBYTES = 1312
CRYPTO_SECRETKEYBYTES = 2560
CRYPTO_BYTES = 2420
SK_SEEDBYTES = 128
SHAKE256_RATE = 136


def polyz_unpack(a: bytes):
  r = [0] * N
  for i in range(N // 4):
    r[4 * i + 0] = a[9 * i + 0]
    r[4 * i + 0] |= a[9 * i + 1] << 8
    r[4 * i + 0] |= a[9 * i + 2] << 16
    r[4 * i + 0] &= 0x3FFFF

    r[4 * i + 1] = a[9 * i + 2] >> 2
    r[4 * i + 1] |= a[9 * i + 3] << 6
    r[4 * i + 1] |= a[9 * i + 4] << 14
    r[4 * i + 1] &= 0x3FFFF

    r[4 * i + 2] = a[9 * i + 4] >> 4
    r[4 * i + 2] |= a[9 * i + 5] << 4
    r[4 * i + 2] |= a[9 * i + 6] << 12
    r[4 * i + 2] &= 0x3FFFF

    r[4 * i + 3] = a[9 * i + 6] >> 6
    r[4 * i + 3] |= a[9 * i + 7] << 2
    r[4 * i + 3] |= a[9 * i + 8] << 10
    r[4 * i + 3] &= 0x3FFFF

    r[4 * i + 0] = GAMMA1 - r[4 * i + 0]
    r[4 * i + 1] = GAMMA1 - r[4 * i + 1]
    r[4 * i + 2] = GAMMA1 - r[4 * i + 2]
    r[4 * i + 3] = GAMMA1 - r[4 * i + 3]
  return r


def polyeta_unpack(a: bytes):
  r = [0] * N
  for i in range(N // 8):
    r[8 * i + 0] = (a[3 * i + 0] >> 0) & 7
    r[8 * i + 1] = (a[3 * i + 0] >> 3) & 7
    r[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7
    r[8 * i + 3] = (a[3 * i + 1] >> 1) & 7
    r[8 * i + 4] = (a[3 * i + 1] >> 4) & 7
    r[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7
    r[8 * i + 6] = (a[3 * i + 2] >> 2) & 7
    r[8 * i + 7] = (a[3 * i + 2] >> 5) & 7

    r[8 * i + 0] = ETA - r[8 * i + 0]
    r[8 * i + 1] = ETA - r[8 * i + 1]
    r[8 * i + 2] = ETA - r[8 * i + 2]
    r[8 * i + 3] = ETA - r[8 * i + 3]
    r[8 * i + 4] = ETA - r[8 * i + 4]
    r[8 * i + 5] = ETA - r[8 * i + 5]
    r[8 * i + 6] = ETA - r[8 * i + 6]
    r[8 * i + 7] = ETA - r[8 * i + 7]
  return r


def polyeta_pack(a):
  r = bytearray(POLYETA_PACKEDBYTES)
  t = [0] * 8
  for i in range(N // 8):
    t[0] = (ETA - a[8 * i + 0]) & 0xFF
    t[1] = (ETA - a[8 * i + 1]) & 0xFF
    t[2] = (ETA - a[8 * i + 2]) & 0xFF
    t[3] = (ETA - a[8 * i + 3]) & 0xFF
    t[4] = (ETA - a[8 * i + 4]) & 0xFF
    t[5] = (ETA - a[8 * i + 5]) & 0xFF
    t[6] = (ETA - a[8 * i + 6]) & 0xFF
    t[7] = (ETA - a[8 * i + 7]) & 0xFF

    r[3 * i + 0] = ((t[0] >> 0) | (t[1] << 3) | (t[2] << 6)) & 0xFF
    r[3 * i + 1] = (
        (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)
    ) & 0xFF
    r[3 * i + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) & 0xFF
  return bytes(r)


def polyt0_unpack(a: bytes):
  r = [0] * N
  for i in range(N // 8):
    r[8 * i + 0] = a[13 * i + 0]
    r[8 * i + 0] |= a[13 * i + 1] << 8
    r[8 * i + 0] &= 0x1FFF

    r[8 * i + 1] = a[13 * i + 1] >> 5
    r[8 * i + 1] |= a[13 * i + 2] << 3
    r[8 * i + 1] |= a[13 * i + 3] << 11
    r[8 * i + 1] &= 0x1FFF

    r[8 * i + 2] = a[13 * i + 3] >> 2
    r[8 * i + 2] |= a[13 * i + 4] << 6
    r[8 * i + 2] &= 0x1FFF

    r[8 * i + 3] = a[13 * i + 4] >> 7
    r[8 * i + 3] |= a[13 * i + 5] << 1
    r[8 * i + 3] |= a[13 * i + 6] << 9
    r[8 * i + 3] &= 0x1FFF

    r[8 * i + 4] = a[13 * i + 6] >> 4
    r[8 * i + 4] |= a[13 * i + 7] << 4
    r[8 * i + 4] |= a[13 * i + 8] << 12
    r[8 * i + 4] &= 0x1FFF

    r[8 * i + 5] = a[13 * i + 8] >> 1
    r[8 * i + 5] |= a[13 * i + 9] << 7
    r[8 * i + 5] &= 0x1FFF

    r[8 * i + 6] = a[13 * i + 9] >> 6
    r[8 * i + 6] |= a[13 * i + 10] << 2
    r[8 * i + 6] |= a[13 * i + 11] << 10
    r[8 * i + 6] &= 0x1FFF

    r[8 * i + 7] = a[13 * i + 11] >> 3
    r[8 * i + 7] |= a[13 * i + 12] << 5
    r[8 * i + 7] &= 0x1FFF

    r[8 * i + 0] = (1 << (D - 1)) - r[8 * i + 0]
    r[8 * i + 1] = (1 << (D - 1)) - r[8 * i + 1]
    r[8 * i + 2] = (1 << (D - 1)) - r[8 * i + 2]
    r[8 * i + 3] = (1 << (D - 1)) - r[8 * i + 3]
    r[8 * i + 4] = (1 << (D - 1)) - r[8 * i + 4]
    r[8 * i + 5] = (1 << (D - 1)) - r[8 * i + 5]
    r[8 * i + 6] = (1 << (D - 1)) - r[8 * i + 6]
    r[8 * i + 7] = (1 << (D - 1)) - r[8 * i + 7]
  return r


def polyt0_pack(a):
  r = bytearray(POLYT0_PACKEDBYTES)
  t = [0] * 8
  for i in range(N // 8):
    t[0] = (1 << (D - 1)) - a[8 * i + 0]
    t[1] = (1 << (D - 1)) - a[8 * i + 1]
    t[2] = (1 << (D - 1)) - a[8 * i + 2]
    t[3] = (1 << (D - 1)) - a[8 * i + 3]
    t[4] = (1 << (D - 1)) - a[8 * i + 4]
    t[5] = (1 << (D - 1)) - a[8 * i + 5]
    t[6] = (1 << (D - 1)) - a[8 * i + 6]
    t[7] = (1 << (D - 1)) - a[8 * i + 7]

    r[13 * i + 0] = (t[0] >> 0) & 0xFF
    r[13 * i + 1] = (t[0] >> 8) & 0xFF
    r[13 * i + 1] |= (t[1] << 5) & 0xFF
    r[13 * i + 2] = (t[1] >> 3) & 0xFF
    r[13 * i + 3] = (t[1] >> 11) & 0xFF
    r[13 * i + 3] |= (t[2] << 2) & 0xFF
    r[13 * i + 4] = (t[2] >> 6) & 0xFF
    r[13 * i + 4] |= (t[3] << 7) & 0xFF
    r[13 * i + 5] = (t[3] >> 1) & 0xFF
    r[13 * i + 6] = (t[3] >> 9) & 0xFF
    r[13 * i + 6] |= (t[4] << 4) & 0xFF
    r[13 * i + 7] = (t[4] >> 4) & 0xFF
    r[13 * i + 8] = (t[4] >> 12) & 0xFF
    r[13 * i + 8] |= (t[5] << 1) & 0xFF
    r[13 * i + 9] = (t[5] >> 7) & 0xFF
    r[13 * i + 9] |= (t[6] << 6) & 0xFF
    r[13 * i + 10] = (t[6] >> 2) & 0xFF
    r[13 * i + 11] = (t[6] >> 10) & 0xFF
    r[13 * i + 11] |= (t[7] << 3) & 0xFF
    r[13 * i + 12] = (t[7] >> 5) & 0xFF
  return bytes(r)


def polyt1_unpack(a: bytes):
  r = [0] * N
  for i in range(N // 4):
    r[4 * i + 0] = ((a[5 * i + 0] >> 0) | (a[5 * i + 1] << 8)) & 0x3FF
    r[4 * i + 1] = ((a[5 * i + 1] >> 2) | (a[5 * i + 2] << 6)) & 0x3FF
    r[4 * i + 2] = ((a[5 * i + 2] >> 4) | (a[5 * i + 3] << 4)) & 0x3FF
    r[4 * i + 3] = ((a[5 * i + 3] >> 6) | (a[5 * i + 4] << 2)) & 0x3FF
  return r


def polyvech_unpack(x: bytes):
  r = []
  k = 0
  for i in range(K):
    h = [0] * N
    if x[OMEGA + i] < k or x[OMEGA + i] > OMEGA:
      raise Exception('malformed hint')
    for j in range(k, x[OMEGA + i]):
      if j > k and x[j] <= x[j - 1]:
        raise Exception('malformed hint')
      h[x[j]] = 1
    r.append(h)
    k = x[OMEGA + i]
  for j in range(k, OMEGA):
    if x[j]:
      raise Exception('malformed hint')
  return r


def poly_challenge(seed):
  c = [0] * N
  buf = [0] * SHAKE256_RATE

  assert len(seed) == CTILDEBYTES

  # Instead of using incremental squeezing, we'll squeeze enough bytes
  # in advance by using digest with a large length to simulate it.
  buf = hashlib.shake_256(seed).digest(N * 10)
  signs = int.from_bytes(buf[:8], byteorder='little')

  buf = list(buf[8:])[::-1]

  for i in range(N - TAU, N):
    b = 0
    while True:
      b = buf.pop()
      if b <= i:
        break

    # Swap and assign coefficient based on sign
    c[i] = c[b]
    c[b] = 1 - 2 * (signs & 1)
    signs >>= 1

  return c


def decompose(a: int) -> (int, int):
  a = int(a % Q)
  if a < 0:
    a += Q
  a1 = (a + 127) >> 7
  a1 = (a1 * 11275 + (1 << 23)) >> 24
  a1 ^= ((43 - a1) >> 31) & a1
  a0 = a - a1 * 2 * GAMMA2
  a0 -= (((Q - 1) // 2 - a0) >> 31) & Q
  return a0, a1  # low, high


def highbits(x: int) -> int:
  a0, a1 = decompose(x)
  return a1


def lowbits(x: int) -> int:
  a0, a1 = decompose(x)
  return a0


def center_q(x: int) -> int:
  x = int(x)
  return x if x < Q // 2 else x - Q


def load_pk(path: str):
  with open(path, 'rb') as f:
    rho = f.read(SEEDBYTES)
    t1 = [polyt1_unpack(f.read(POLYT1_PACKEDBYTES)) for i in range(K)]
  return rho, t1


def load_pk_mat(path: str):
  with open(path, 'rb') as f:
    flatten = list(map(int, f))
    assert len(flatten) == 256 * 4 * 4
  # Unflatten to A[K][L][N]
  A = []
  for i in range(K):
    row = []
    for j in range(L):
      poly = [0] * N
      for n in range(N):
        poly[n] = flatten[i * L * N + j * N + n]
      row.append(poly)
    A.append(row)
  return A


def load_sk(path: str):
  with open(path, 'rb') as f:
    _ = f.read(SK_SEEDBYTES)
    s1 = [polyeta_unpack(f.read(POLYETA_PACKEDBYTES)) for _ in range(L)]
    s2 = [polyeta_unpack(f.read(POLYETA_PACKEDBYTES)) for _ in range(K)]
    t0 = [polyt0_unpack(f.read(POLYT0_PACKEDBYTES)) for i in range(K)]
  return s1, s2, t0


def load_sig_stream(f):
  c = poly_challenge(f.read(CTILDEBYTES))
  z = [polyz_unpack(f.read(POLYZ_PACKEDBYTES)) for _ in range(L)]
  h = polyvech_unpack(f.read(POLYVECH_PACKEDBYTES))
  return c, z, h


if __name__ == '__main__':
  import os
  from tqdm import trange

  for _ in trange(100000):
    a = os.urandom(POLYETA_PACKEDBYTES)
    b = polyeta_pack(polyeta_unpack(a))
    assert a == b, (a, b)

  for _ in trange(100000):
    a = os.urandom(POLYT0_PACKEDBYTES)
    b = polyt0_pack(polyt0_unpack(a))
    assert a == b, (a, b)
