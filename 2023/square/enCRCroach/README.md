# enCRCroach

## CRC Bit Flipping Attack

- **CRC(A ⊕ B) = CRC(A) ⊕ CRC(B)**

- *encrypt_token* function generates a token using AES in CTR mode.
- mac = CRC(iv + user_bytes + nonce)
- encrypt_token(user_bytes + nonce + mac)
