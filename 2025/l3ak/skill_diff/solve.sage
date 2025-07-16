import hashlib

sb = (238, 180, 132, 65, 223, 139, 245, 252, 68, 184, 227, 73, 30, 225, 253, 204, 86, 7, 202, 243, 41, 213, 118, 167, 136, 193, 236, 107, 33, 13, 183, 229, 105, 55, 182, 94, 155, 109, 18, 119, 186, 52, 224, 221, 131, 83, 165, 110, 113, 185, 44, 209, 228, 157, 148, 143, 108, 134, 101, 141, 80, 31, 40, 23, 210, 154, 244, 181, 22, 226, 97, 151, 251, 76, 102, 125, 45, 158, 240, 137, 25, 235, 248, 53, 153, 166, 164, 208, 220, 198, 106, 88, 201, 163, 38, 121, 10, 82, 84, 173, 215, 161, 63, 24, 250, 57, 66, 4, 21, 1, 5, 43, 27, 92, 58, 218, 112, 114, 171, 103, 177, 99, 50, 87, 211, 122, 0, 39, 138, 75, 46, 239, 2, 6, 91, 176, 178, 127, 237, 169, 133, 34, 231, 15, 11, 81, 49, 69, 62, 123, 212, 71, 90, 249, 172, 98, 233, 254, 255, 203, 116, 8, 128, 200, 74, 145, 205, 187, 222, 59, 70, 16, 26, 207, 160, 217, 191, 246, 179, 72, 150, 140, 89, 14, 64, 174, 37, 232, 242, 170, 19, 47, 216, 77, 9, 67, 104, 36, 135, 35, 147, 60, 247, 117, 129, 56, 175, 196, 189, 149, 206, 42, 152, 192, 120, 51, 96, 85, 93, 144, 146, 126, 100, 48, 29, 32, 194, 130, 197, 162, 188, 61, 142, 95, 3, 159, 28, 124, 241, 190, 219, 230, 156, 20, 214, 54, 199, 111, 168, 79, 234, 195, 17, 12, 115, 78)
inv_sbox = [0]*256
for i, c in enumerate(sb):
    inv_sbox[c] = i

M = Matrix(Zmod(256), [(0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0),
 (0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0),
 (0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0),
 (0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0),
 (0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
 (0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
 (1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
 (0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0),
 (0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0),
 (1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1),
 (0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0),
 (0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1),
 (0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0),
 (1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0),
 (1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1),
 (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]) 
inv_M = M.inverse()

aff = [[109, 211], [123, 254], [81, 20], [129, 182], [251, 74], [57, 11], [213, 44], [155, 52], [205, 146], [239, 12], [123, 218], [143, 178], [63, 228], [153, 223], [237, 1], [133, 72]]
inv_aff = [[inverse_mod(a, 256), -inverse_mod(a, 256)*b] for a, b in aff]

def matrix_multiply(input_vec):
    """Multiply input vector by the matrix M modulo 256"""
    output = [0] * 16
    for i in range(16):
        total = 0
        for j in range(16):
            total = (total + input_vec[j] * M[i][j]) % 256
        output[i] = total
    return output

def encrypt_block(block, master_key):
    """Encrypt a 16-byte block with the given master key"""
    # Generate round keys
    round_keys = generate_round_keys(master_key)
    state = block.copy()
    
    # Initial key addition
    state = [(state[i] + round_keys[0][i]) % 256 for i in range(16)]
    
    # 3 rounds
    for r in range(3):
        # Linear layer
        state = matrix_multiply(state)
        
        # Non-linear layer
        for i in range(16):
            a, b = aff[i]
            state[i] = (a * state[i] + b) % 256
            state[i] ^= 1
            state[i] = sb[state[i]]
            state[i] = (state[i] + round_keys[r+1][i]) % 256
    
    return state

def generate_round_keys(master_key):
    """Generate round keys from master key using SHA-256"""
    round_keys = [master_key.copy()]
    for _ in range(3):
        h = hashlib.sha256()
        h.update(bytes(round_keys[-1]))
        h.update(bytes(master_key))
        next_key = list(h.digest()[:16])
        round_keys.append(next_key)
    return round_keys

def recover_key(url):
    # Craft known plaintext: "FLAG{" + 11 null bytes
    plaintext = b'FLAG{' + b'\x00' * 11
    files = {'file': ('input.bin', plaintext)}
    
    # Upload file to oracle
    response = requests.post(url + '/oracle', files=files)
    
    # Extract encrypted zip
    zip_data = BytesIO(response.content)
    with ZipFile(zip_data, 'r') as zip_ref:
        with zip_ref.open('input.enc') as f:
            our_enc = f.read()
        with zip_ref.open('flag.enc') as f:
            flag_enc = f.read()
    
    # Get first block of each
    our_enc_block = list(our_enc[:16])
    flag_enc_block = list(flag_enc[:16])
    
    # Known prefix of flag's first block
    known_prefix = list(b'FLAG{')
    unknown_len = 11
    
    # Brute-force unknown part of flag's first block
    for candidate in itertools.product(range(256), repeat=unknown_len):
        candidate_block = known_prefix + list(candidate)
        # Encrypt candidate block with our plaintext's encryption
        # (uses same key since same session)
        candidate_enc = encrypt_block(candidate_block, our_enc_block)
        if candidate_enc == flag_enc_block:
            # Derive master key from our plaintext and its encryption
            master_key = [(our_enc_block[i] - plaintext[i]) % 256 
                          for i in range(16)]
            return master_key
    
    raise ValueError("Key recovery failed")

def decrypt_flag(url, master_key):
    # Retrieve encrypted flag again (or use stored value)
    plaintext = b'FLAG{' + b'\x00' * 11
    files = {'file': ('input.bin', plaintext)}
    response = requests.post(url + '/oracle', files=files)
    zip_data = BytesIO(response.content)
    with ZipFile(zip_data, 'r') as zip_ref:
        with zip_ref.open('flag.enc') as f:
            flag_enc = f.read()
    
    # Decrypt each block of flag.enc
    flag_blocks = [list(flag_enc[i:i+16]) for i in range(0, len(flag_enc), 16)]
    decrypted_blocks = []
    for block in flag_blocks:
        decrypted = encrypt_block(block, master_key)  # Encryption is self-inverse with modified key
        decrypted_blocks.extend(decrypted)
    
    # Remove padding and convert to string
    flag = bytes(decrypted_blocks).rstrip(b'\x00').decode()
    return flag
