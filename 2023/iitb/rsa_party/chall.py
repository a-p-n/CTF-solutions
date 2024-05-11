from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random.random import getrandbits
from secret import flag

keys_layer1 = [RSA.generate(1024, e = 5) for _ in range(6)]
keys_layer2 = [RSA.generate(2512, e = 3) for _ in range(6)]

def null_pad(s : bytes, width : int) -> bytes:
    return s + b"\x00"*((width-len(s)*8)//8)

def interact(identity : int):
    key_layer1 = keys_layer1[identity]
    key_layer2 = keys_layer2[identity]

    f = bytes_to_long(flag)
    assert f.bit_length() < key_layer1.n.bit_length()

    ct_layer1 = long_to_bytes(pow(f, key_layer1.e, key_layer1.n))

    ct_layer1_padded  = null_pad(f"{{encryption: {ct_layer1.hex()}}}".encode(), 2512-128-1)
    pt_layer2 = bytes_to_long(ct_layer1_padded) + getrandbits(128)
    assert pt_layer2.bit_length() < key_layer2.n.bit_length()

    ct_layer2 = long_to_bytes(pow(pt_layer2, key_layer2.e, key_layer2.n))
    
    print(f"Public Moduli: {key_layer1.n} ; {key_layer2.n}")
    print(f"My Interactive Talk: {ct_layer2.hex()}")





def party():
    print("Welcome to the RSA Party!")
    
    while True:
        print()
        print("Party members are Alice (1), Bob (2), Carol (3), Dick (4), Eve (5), and Fin (6)!")
        identity = int(input("Enter ID of member you want to interact with: "))
        if 1 <= identity <= 6:
            interact(identity-1)
        else:
            print("Enter a valid ID!")
        



if __name__ == "__main__":
    party()
    try:
        party()
    except Exception as error:
        print(repr(error))

