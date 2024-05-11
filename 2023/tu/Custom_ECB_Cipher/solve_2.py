from Crypto.Util.number import bytes_to_long, long_to_bytes

c = bytes.fromhex("e34a707c5c1970cc6375181577612a4ed07a2c3e3f441d6af808a8acd4310b89bd7e2bb9")

blocks = [bytes_to_long(c[i:i+4]) for i in range(0, len(c), 4)]


def convert(msg, x):
    print(f"input {msg}")
    msg = msg ^ msg >> x
    print(f"after shift x {msg}")
    msg = msg ^ msg << 13 & 275128763  # 0x106621bb
    print(f"after shift 13 {msg}")
    msg = msg ^ msg << 20 & 2186268085 # 0x824fcdb5
    print(f"after shift 20 {msg}")
    msg = msg ^ msg >> 14
    print(f"after shift 14 {msg}")
    return msg

def deconvert(msg, x):
    # msg = msg ^ msg >> 14
    part = msg ^ (msg & 0xfffc0000) >> 14
    msg = msg ^ part >> 14
    print(f"after shift 20 {msg}")

    # msg = msg ^ msg << 20 & 2186268085
    msg = msg ^ msg << 20 & 2186268085
    print(f"after shift 13 {msg}")

    # msg = msg ^ msg << 13 & 275128763
    part = msg ^ (msg & 0x1fff) << 13 & 275128763
    msg = msg ^ (part & 0x3ffffff) << 13 & 275128763
    print(msg)
    print(f"after shift x {msg}")

    # msg = msg ^ msg >> x
    mask = int("1"*x + "0" * (32-x), 2)
    adder = mask
    part = msg
    while mask != 2**32 - 1:
        part = msg ^ (part & mask) >> x
        mask = adder | mask >> x
    print(f"input {part}")
    return part

def detransform(blocks, x):
    new_message = b""
    for b in blocks:
        dec = deconvert(b, x)
        assert b == convert(dec, x)
        new_message += long_to_bytes(dec)
    return new_message

# test deconvert if debug is enabled
for i in range(1,33):
    dec = detransform(blocks, i)
    if all([c >= 0x20 and c < 0x7f for c in dec]):
        print(dec.decode())
    else:
        print(str(dec))