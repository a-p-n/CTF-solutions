# enCRCroach

### Implementation

```python
import hashlib
import os
import secrets

import fastcrc
import werkzeug.security
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, Response, request, send_from_directory

app = Flask(__name__)

SERVER_KEY = bytes.fromhex(os.environ.get("SERVER_KEY", ""))
IV_LEN = 16
# USER_LEN = can potentially vary
NONCE_LEN = 42
MAC_LEN = 8
KEY_LEN = 32

USER_DB = {
    # Someone keeps hacking us and reading out the admin's /flag.txt.
    # Disabling this account to see if that helps.
    # "admin": "7a2f445babffa758471e3341a1fadce9abeff194aded071e4fd48b25add856a7",

    # Other accounts. File a ticket similar to QDB-244321 to add or modify passwords.
    "azure": "9631758175d2f048db1964727ad2efef4233099b97f383e4f1e121c900f3e722",
    "cthon": "980809b1482352ae59be5d3ede484c0835b46985309a04ac1bad70b22a167670",
}


def response(text, status=200):
    return Response(text, status=status, mimetype="text/plain")


@app.route("/", methods=["GET", ])
def root():
    return response("""Endpoints:
  - /auth?user=<user>: Auth a user with an optional password. Returns an auth token.
  - /read/<path>?token=<token>: Read out a file from a user's directory. Token required.
""")


@app.route("/auth", methods=["GET", ])
def auth():
    """Return a token once the user is successfully authenticated.
    """
    user = request.args.get("user")
    password = request.args.get("password", "")
    if not user or user not in USER_DB:
        return response("Bad or missing 'user'", 400)

    password_hash = USER_DB[user]
    given = hashlib.pbkdf2_hmac("SHA256", password.encode(), user.encode(), 1000).hex()
    if password_hash != given:
        return response("Bad 'password'", 400)

    # User is authenticated! Return a super strong token.
    return response(encrypt_token(user, SERVER_KEY).hex())


@app.route("/read", defaults={"path": None})
@app.route("/read/<path>", methods=["GET", ])
def read(path: str):
    """Read a static file under the user's directory.

    Lists contents if no path is provided.

    Decrypts the token to auth the request and get the user's name.
    """
    try:
        user = decrypt_token(bytes.fromhex(request.args.get("token", "")), SERVER_KEY)
    except ValueError:
        user = None

    if not user:
        return response("Bad or missing token", 400)

    user_dir = werkzeug.security.safe_join("users", user)

    if path is None:
        listing = "\n".join(sorted(os.listdir(os.path.join(app.root_path, user_dir))))
        return response(listing)

    return send_from_directory(user_dir, path)


def encrypt_token(user: str, key: bytes) -> bytes:
    """Encrypt the user string using "authenticated encryption".

    JWTs and JWEs scare me. Too many CVEs! I think I can do better...

    Here's the token format we use to encrypt and authenticate a user's name.
    This is sent to/from the server in ascii-hex:
      len :  16    variable      42      8
      data:  IV ||   USER   || NONCE || MAC
                  '------------------------' Encrypted
    """
    assert len(key) == KEY_LEN

    user_bytes = user.encode("utf-8")

    iv = secrets.token_bytes(IV_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    mac = gen_mac(iv + user_bytes + nonce)

    ciphertext = cipher.update(user_bytes + nonce + mac) + cipher.finalize()

    return iv + ciphertext


def decrypt_token(token: bytes, key: bytes) -> [None, str]:
    assert len(key) == KEY_LEN

    iv, ciphertext = splitup(token, IV_LEN)
    if not iv or not ciphertext:
        return None

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    plaintext = cipher.update(ciphertext) + cipher.finalize()

    user_bytes, nonce, mac = splitup(plaintext, -(NONCE_LEN + MAC_LEN), -MAC_LEN)
    if not user_bytes or len(nonce) != NONCE_LEN or len(mac) != MAC_LEN:
        return None

    computed = gen_mac(iv + user_bytes + nonce)
    if computed != mac:
        return None

    return user_bytes.decode("utf-8")


def gen_mac(data: bytes) -> bytes:
    # A 64-bit CRC should be pretty good. Faster than a hash, and can't be brute forced.
    crc = fastcrc.crc64.go_iso(data)
    return int.to_bytes(crc, length=MAC_LEN, byteorder="big")


def splitup(data: bytes, *indices):
    last_index = 0
    for index in indices:
        yield data[last_index:index]
        last_index = index
    yield data[last_index:]


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=os.environ.get("FLASK_SERVER_PORT"), debug=False)
```

### Description of the challenge
- We have been given Flask server. Key parameters have been already set and it remains the same. We are also give the length of iv, nonce, mac and the key.
    - iv - 16
    - nonce - 42
    - mac - 8
    - key - 32
- "USER_DB" is a dictionary that stores the usernames "azure" and "cthon" along with its hashes password. The password is hashed in **SHA256**.
- The server contains two "endpoints" for interaction :
    1. */auth* - Return a token once the user is successfully authenticated.
    2. */read* - Decrypts the token to auth the request and get the user's name.

#### AUTHENTICATION
* **/auth?user=user-name&password=password** - Auth a user with a password. Returns an auth token.
* Upon receiving a user and password, the server validates the user and password against the user database.
* If the authentication is successful, the server generates an authentication token using a custom format.
 
#### TOKEN FORMAT
* Format of the token is 
`IV || USER || NONCE || MAC`
* The components of the token :
    - IV: Initialization Vector for AES-CTR encryption.
    - USER: User data, encrypted using AES-CTR mode.
    - NONCE: A randomly generated nonce.
    - MAC: Message Authentication Code generated using a 64-bit CRC.

#### Encryption and MAC Generation:
- The encrypt_token function handles the encryption of user data using AES-CTR mode.
- The gen_mac function calculates a 64-bit CRC for a given set of data, serving as the MAC.

#### Token Decryption:
- The /read endpoint allows reading files from a user's directory and requires a valid authentication token.
- The decrypt_token function decrypts the token, verifies the MAC, and returns the user data.

#### Flag Access:
- Once we give the modified token to access the /read/flag.txt endpoint we will get the flag.

### Working of CRC
![image](https://hackmd.io/_uploads/r1I4YhEr6.png)

- There are 2 sides : 1. Sender Side 2. Receiver Side

1. Sender Side:
    - The sender first calculates the CRC value for the data to be sent. This is done by treating the data as a binary number and dividing it by a generator polynomial. The remainder of this division is the CRC value.
    - The sender then appends the CRC value to the end of the data.
    - The data along with the CRC value is then sent to the receiver.

![image](https://hackmd.io/_uploads/rkIZoyrHa.png)

2. Receiver Side:
    - The receiver receives the data along with the CRC value.
    - The receiver then calculates the CRC value for the received data in the same way as the sender.
    - The receiver compares the calculated CRC value with the received CRC value. If they match, the data is assumed to be intact. If they don't match, the data is assumed to be corrupted.

![image](https://hackmd.io/_uploads/SJsfsyHSa.png)

- Example -  The data bit to be sent is 100100, and the polynomial equation is x3+x2+1.

    - Data bit - 100100

    - Divisor (k) - 1101 (Using the given polynomial)

    - Appending Zeros - (k-1) > (4-1) > 3

    - Dividend :100100000

### VULNERABILITY OF CRC
- MAC is encrypted using CRC that is vulnerable to bit flipping attack since xor is the main fucntion involved in CRC. We can change few bits of the data without invalidating the CRC.
```
CRC(A ⊕ B) = CRC(A) ⊕ CRC(B) ⊕ CRC(00...)
```

### Challenge Objective:

- The challenge involves exploiting the CRC64-based MAC for a bit-flipping attack.
- We need to modify the user data in the token while maintaining a valid CRC64-based MAC.
- Make a payload that, when XORed with the original token, produces a modified token with a valid MAC could be the goal.

### Solution
- We were given a hint to find the password of a user. 
    _Other accounts. File a ticket similar to QDB-244321 to add or modify passwords._
- When we search for QDB-244321 we get the password for azure from [here](https://www.social-engineer.org/wiki/archives/BlogPosts/IRCpassword.html).
- We provide the username and the password in the url and we will get a token.
- First we need to change the user.
```
payload = xor(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*50, token)
```
- Here, we xor the token with the xor("admin", "azure") which will give us "admin" back.
- Now we need to change the crc value without invalidating the CRC.
```
mac = xor(gen_mac(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*42), gen_mac(b'\x00'*63))
```
- This will give us the _crc(xor(xor(b'admin', b'azure'), b'\x00'* 5))_ which can also be written as:
```
crc("admin") ⊕ crc("azure") ⊕ crc(b'\x00'* 5)
```
- According to the linear property of CRC:
```
crc("admin") ⊕ crc("azure") ⊕ crc(b'\x00'* 5) = crc("admin") ⊕ crc("azure")
```
- Since the token is of "azure" the mac will be :
```
crc("admin") ⊕ crc("azure") ⊕ crc("azure") = crc("admin")
```
- We have got the mac for the admin user. When we provide this payload we will get the flag.

### Script
```python
import fastcrc
import requests
from pwn import xor

def gen_mac(data: bytes) -> bytes:
    crc = fastcrc.crc64.go_iso(data)
    return int.to_bytes(crc, length=8, byteorder="big")

token = bytes.fromhex(requests.get("http://184.72.87.9:8002/auth?user=azure&password=hunter2").text)

payload = xor(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*50, token)

a = gen_mac(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*42)
b = gen_mac(b'\x00'*63)
mac = xor(a, b)

payload = xor(payload, b'\x00'*63 + mac)

print(requests.get("http://184.72.87.9:8002/read/flag.txt?token="+payload.hex()).text)
```

### flag{r0llin_my_0wn_crypt0_311c4f2a}

