from Crypto.Util.Padding import unpad
from pwn import context, remote
from tqdm import tqdm

io = remote("challs.umdctf.io", 32345)
# context.log_level = "debug"
# zeroing_iv = [115, 31, 243, 237, 92, 244, 250, 16, 19, 36, 188, 132, 163, 133, 158, 3] ==> p1
# zeroing_iv = [178, 222, 221, 30, 15, 131, 123, 76, 21, 238, 196, 47, 32, 238, 111, 66] ==> p2
# zeroing_iv = [155, 125, 176, 177, 2, 218, 61, 199, 144, 236, 128, 71, 155, 137, 249, 255] ==> p3
def single_block_attack(iv , ct):
    zeroing_iv = [0]*16

    for pad_val in range(1, 16+1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in tqdm(range(256)):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)

            try:
                io.sendlineafter(b"valid padding:\n", (iv+ct).hex())
                res = io.recvline()
                if b"wrong ciphertext size!" not in res and b"invalid padding :(\n" not in res:
                    if pad_val == 1:
                        padding_iv[-2] ^= 1
                        iv = bytes(padding_iv)

                        io.sendlineafter(b"valid padding:\n", (iv+ct).hex())
                        res1 = io.recvline()
                        if b"wrong ciphertext size!" in res1 or b"invalid padding :(\n" in res1:
                            continue
                    print("yo",iv)
                    print(zeroing_iv)
                    break
            except:
                print(zeroing_iv)
                io.close()
                exit()

        zeroing_iv[-pad_val] = candidate ^ pad_val
        print(zeroing_iv)
    return zeroing_iv


def full_attack(iv, ct):
    assert len(iv) == 16 and len(ct) % 16 == 0

    msg = iv + ct
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    result = b''

    iv = blocks[0]
    for block in range(len(blocks[1:])):
        dec = single_block_attack(blocks[block], blocks[block+1])
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(blocks[block], dec))
        result += pt
        iv = blocks[block+1]
        print(result)

    return result

if __name__ == "__main__":
    iv = bytes.fromhex("2652b7ae08b281594c488cf2e6daee43")
    ct = bytes.fromhex("d697937950b3090d56828170609a3b23f836e3cc0ed631cb9ce08c4b9785f5f3db5dee5f44adaad3630303062b61d5fa")

    result = full_attack(iv, ct)
    print("FLAG :", unpad(result, 16))
