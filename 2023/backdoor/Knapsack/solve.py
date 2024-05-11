from sage.all import *
from itertools import combinations
from Crypto.Cipher import AES
import hashlib
from tqdm import tqdm
from Crypto.Util.number import *


def solve_subset(arr_, s, brute):
    for arr in tqdm(combinations(arr_, len(arr_) - brute)):
        N = ceil(sqrt(len(arr)) / 2)
        M = identity_matrix(QQ, len(arr))
        M = M.augment(N*vector(arr))
        M = M.stack(vector([-1/2 for _ in range(len(arr))] + [-N*s]))

        for row in M.LLL():
            for row in (row, -row):
                kk = [i+1/2 for i in row][:-1]
                if not all([i in (0, 1) for i in kk]):
                    continue
                subset = [xx for xx, k in zip(arr, kk) if k]
                if sum(subset) == s:
                    return subset


arr_ = [600848253359, 617370603129, 506919465064, 218995773533, 831016169202, 501743312177, 15915022145, 902217876313, 16106924577, 339484425400, 372255158657, 612977795139, 755932592051, 188931588244, 266379866558, 661628157071, 428027838199, 929094803770, 917715204448, 103431741147,
        549163664804, 398306592361, 442876575930, 641158284784, 492384131229, 524027495955, 232203211652, 213223394430, 322608432478, 721091079509, 518513918024, 397397503488, 62846154328, 725196249396, 443022485079, 547194537747, 348150826751, 522851553238, 421636467374, 12712949979]
s = 7929089016814
brute = 1  # lmao
subset = solve_subset(arr_, s, brute)

secret = ""
for i in arr_:
    if i in subset:
        secret += "1"
    else:
        secret += "0"
secret = secret[::-1]
secret = long_to_bytes(int(secret, 2))

ct = bytes.fromhex('af95a58f4fbab33cd98f2bfcdcd19a101c04232ac6e8f7e9b705b942be9707b66ac0e62ed38f14046d1cd86b133ebda9')
key = hashlib.sha256(secret).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(ct))
# flag{N0t_r34dy_f0r_M3rkl3-H3llman}
