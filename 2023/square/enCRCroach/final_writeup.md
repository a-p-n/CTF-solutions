# enCRCroach

### IMPLEMENTATION

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

### DESCRIPTION OF THE CHALLENGE
- Provided by a Flask server with predefined key parameters, as follows:
    - IV (initial vector): 16 bytes
    - Nonce: 42 bytes
    - MAC (Message Access Address): 8 bytes
    - Key: 32 bytes
- The server uses the "USER_DB" dictionary which securely stores the "azure" and "cthon" user names with their hashed passwords. The password hashing algorithm used here is **SHA256**.
- There are two endpoints for communication:
    1. **/auth** - This endpoint returns an authentication token when the user succeeds.
    2. **/read** - Used to decrypt the token to validate the request and obtain the username.

#### AUTHENTICATION
- The certification process has the following conclusions.
    **/auth?user=username&password=password**
- After receiving the username and password, the server performs the following tasks.
    1. Validates the assigned user name and password with respect to information in the user database.
    2. If the authentication is successful, the server proceeds to generate an authentication token using a custom format.
- The configuration described above ensures that the authentication system on the Flask server is secure and properly configured. It includes robust mechanisms for verifying user credentials and creating trusted authentication tokens.

#### TOKEN FORMAT
- The token follows a specific format: `IV || User || NONCE || MAC`
- The value of tokens includes:
    - **IV:** The initial vector is used for AES-CTR encryption.
    - **USER:** User data, encrypted using AES-CTR mode.
    - **NONCE:** A random nonce.
    - **MAC:** Message Authentication Code generated using 64-bit CRC

#### MESSAGE AUTHENTICATION CODE (MAC)
- A Message Authentication Code (MAC) is a short piece of data used to verify and protect the integrity of a message.
- The MAC serves the purpose of confirming that the message originates from the correct sender and has not undergone any unauthorized modifications.
- Its implementation adds an extra layer of security to the communication process.

#### ENCRYPTION AND MAC GENERATION
- The `encrypt_token` function manages the encryption of user data using AES-CTR mode, ensuring the confidentiality of the information.
- Additionally, the `gen_mac` function computes a 64-bit CRC, serving as the Message Authentication Code (MAC), to authenticate the data.

#### TOKEN DECRYPTION
- The /read endpoint allows reading files from a user's directory and requires a valid authentication token.
- The decrypt_token function decrypts the token, verifies the MAC, and returns the user data.

#### FLAG ACCESS
- When you use the modified token to access `/read/flag.txt`, you unlock the flag.

### WORKING OF CRC
- Cyclic Redundancy Check (CRC) serves as a method for error detection and correction, ensuring data integrity during transmission.
- CRC uses a systematic approach to double-check if the data is accurate.

![image](https://hackmd.io/_uploads/r1I4YhEr6.png)

#### SENDER SIDE:

1. The sender starts by calculating a CRC value for the data to be sent. This involves treating the data as a binary number and dividing it by a generator polynomial. The resulting remainder becomes the CRC value.
2. The sender appends this CRC value to the end of the original data.
3. The sender then sends the data attached with CRC value to the receiver.

![image](https://hackmd.io/_uploads/rkIZoyrHa.png)

#### RECEIVER SIDE

1.  The receiver, upon receiving the data along with the CRC value
2.  The receiver then calculates its own CRC value using the same method employed by the sender.
3.  A comparison is made between the calculated CRC value and the received CRC value. If they match, the data is considered intact. If there's a mismatch, the data is presumed to be corrupted.

![image](https://hackmd.io/_uploads/SJsfsyHSa.png)

#### EXAMPLE

- Consider the following scenario with a data bit to be sent as "100100" and a polynomial equation "x^3 + x^2 + 1":

-   Data bit: 100100
-   Divisor (k): 1101 (derived from the given polynomial)
-   Appending Zeros: (k-1) -> (4-1) -> 3
-   Dividend: 100100000

- This process shows how CRC ensures data integrity by detecting errors in transmitted data.

### VULNERABILITY OF CRC
- The Message Authentication Code (MAC) is generated using CRC on the concatenation of IV, user_bytes, and nonce and then it is being encrypted in AES-CTR mode.
- Contrary to a typical bit-flipping attack scenario, where altering bits would invalidate the CRC, CRC exhibits a unique property.
- After flipping bits on the CTR mode encrypted token, the CRC becomes invalid. However, CRC's specific computational nature allows for the derivation of a new CRC from the old one.
- This property, illustrated by the formula:
```
CRC(A ⊕ B ⊕ (00...)) = CRC(A) ⊕ CRC(B) ⊕ CRC(00...)
```

### AES-CTR MODE
- AES-CTR (Advanced Encryption Standard Counter Mode) is a block cipher mode that ensures secure and efficient data encryption.
- The process begins with the selection of a unique Initialization Vector (IV). The IV is a random value, typically the same length as the block size of the cipher (e.g., 128 bits for AES).
- A counter value is created, often by incrementing a nonce (number used once). The combination of the IV and the counter produces a unique input for each block.
- The IV and counter value are encrypted using the block cipher (AES) with the secret key. This encryption process generates a pseudorandom key stream.
- The generated key stream is then XORed with the plaintext block, producing the ciphertext.
- The counter is incremented for the next block, and the process repeats. This allows parallel encryption of multiple blocks.
- Each block is encrypted simultaneously.

![image](https://hackmd.io/_uploads/H19RcAcBa.png)

### CHALLENGE OBJECTIVE:
- The challenge at hand revolves around exploiting the CRC64-based MAC encrypted in AES-CTR mode through a bit-flipping attack.
- The goal is to manipulate the user data in the token while ensuring a valid CRC64-based MAC.
- Creating a payload that, when XORed with the original token, results in a modified token with a valid MAC is the primary objective.

### SOLUTION
- Discovered a user's password from a hint given in the source code :
    _Other accounts. File a ticket similar to QDB-244321 to add or modify passwords._
- Upon investigating ticket QDB-244321, the password for the "azure" account was found [here](https://www.social-engineer.org/wiki/archives/BlogPosts/IRCpassword.html).
- To get the token, append the username and the password to the url.
- To change the user, utilize XOR operations, effectively changing the user to "admin" while preserving the CRC integrity.
- Xor the token with the xor("admin", "azure") which will give us "admin" back.
```
payload = xor(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*50, token)
```
- Next, to manipulate the CRC value without invalidating it, XOR two MAC values:
```
mac = xor(gen_mac(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*42), gen_mac(b'\x00'*63))
```
- This XOR operation leveraged the linear property of CRC, simplifying the expression to `crc("admin") ⊕ crc("azure")`.
```
crc("admin") ⊕ crc("azure") ⊕ crc(b'\x00'* 5) = crc("admin") ⊕ crc("azure")
```
- As a result, the calculated MAC for the "admin" user was obtained.
```
crc("azure") ⊕ crc("admin") ⊕ crc("azure") = crc("admin")
```
- Finally, submitting this payload with the modified MAC value provided access to the flag. 

### SCRIPT
```python
import fastcrc
import requests
from pwn import xor

# Function to generate MAC
def gen_mac(data: bytes) -> bytes:
    crc = fastcrc.crc64.go_iso(data)  # CRC 64-bit
    return int.to_bytes(crc, length=8, byteorder="big")

# Obtaining token with user=azure and password=hunter2
token = bytes.fromhex(requests.get("http://184.72.87.9:8002/auth?user=azure&password=hunter2").text)

# Creating a payload with admin user
payload = xor(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*50, token)

# Generating MAC for admin user
a = gen_mac(b'\x00'*16+xor(b'admin', b'azure')+b'\x00'*42)
b = gen_mac(b'\x00'*63)
mac = xor(a, b)

# Modifying the MAC to be valid for the admin user
payload = xor(payload, b'\x00'*63 + mac)

# Accessing the flag with the modified payload
print(requests.get("http://184.72.87.9:8002/read/flag.txt?token="+payload.hex()).text)
```

### flag{r0llin_my_0wn_crypt0_311c4f2a}

