import os
import signal
import base64
import ed25519

from Crypto.Cipher import AES

KEY = os.urandom(32)
PHRASE = b'I want flag'

def print_menu():
    print('''
[1] create key
[2] sign message
[3] verify signature
    '''.strip())

    return input('> ')

def decrypt_key(key):
    """
    Decrypt the secret part of the key and reconstruct key object
    """
    key = base64.b64decode(key)

    nonce, sk, tag, vk = key[:12], key[12:44], key[44:60], key[60:]

    aes = AES.new(KEY, nonce=nonce, mode=AES.MODE_GCM)

    sk = aes.decrypt_and_verify(sk, tag)

    key = ed25519.SigningKey(sk_s=sk + vk)

    return key

def encrypt_key(key):
    """
    Encrypt the secret part of the key
    """

    key = key.sk_s

    sk, vk = key[:32], key[32:]

    nonce = os.urandom(12)

    aes = AES.new(KEY, nonce=nonce, mode=AES.MODE_GCM)

    sk, tag = aes.encrypt_and_digest(sk)

    return base64.b64encode(nonce + sk + tag + vk).decode()

def generate_key():
    sk, _ = ed25519.create_keypair()
    out = encrypt_key(sk)

    print(f'Your key is: {out}')


def sign_message():
    key = input('Hand me your  key: ').strip()
    key = decrypt_key(key)

    msg = input('Which message to sign?: ').strip().encode()

    if msg == PHRASE:
        print("I'm sorry Dave, I'm afraid I can't do that")
        return

    sig = key.sign(msg)
    sig = base64.b64encode(sig).decode()

    print(f'Signature: {sig}')


def verify_signature():
    key = input('Hand me your key: ').strip()
    key = decrypt_key(key)

    msg = input('Which message to verify?: ').strip().encode()

    sig = input('What is the signature?: ').strip().encode()
    sig = base64.b64decode(sig)

    pk = key.get_verifying_key()

    try:
        pk.verify(sig, msg)
        print("The signature is valid")

        if msg == PHRASE:
            print(os.environ["FLAG"])
    except ed25519.BadSignatureError:
        print("The signature is invalid")


def main():
    signal.alarm(300)

    while True:
        option = print_menu()

        match option:
            case '1':
                generate_key()
            case '2':
                sign_message()
            case '3':
                verify_signature()
            case _:
                print('Invalid option')

if __name__ == '__main__':
    main()
