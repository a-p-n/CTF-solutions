import numpy as np 
from sage.all import *

G_pub = np.load('alice_pub.npy')
c_hex = "33b4ba0c3c11ad7e298b79de7261c5dd8edd7b537007b383cad9f38dbcf584e66a07c9808edad6e289516f3c6cc4186686f3a7fc8e1603e80aba601efe82e8cf2f6a28aa405cf7419b9dd1f01925c5"
    
R = 6
N = 2**R - 1  # 63
K = N - R     # 57

def load_matrix_from_npy(filename, ring=GF(2)):
    mat_np = np.load(filename)
    mat = matrix(ring, mat_np.tolist())
    return mat

def hex_to_bits(hex_string):
    c_int = int(hex_string, 16)
    c_bits_str = bin(c_int)[2:]  # Remove '0b' prefix
    return [int(b) for b in c_bits_str]

def pad_bits_to_blocks(bits, block_size):
    pad_len = (-len(bits)) % block_size
    bits_padded = [0] * pad_len + bits
    
    blocks = []
    for i in range(0, len(bits_padded), block_size):
        block = bits_padded[i:i+block_size]
        if len(block) == block_size:
            blocks.append(block)
    
    return blocks

def bits_to_bytes(bits):
    if not bits:
        return b''
    
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            byte_bits.extend([0] * (8 - len(byte_bits)))
        
        byte_val = 0
        for j, bit in enumerate(byte_bits):
            byte_val |= (bit << (7-j))
        bytes_list.append(byte_val)
    
    return bytes(bytes_list)

G_pub = load_matrix_from_npy('alice_pub.npy')
print(f"Public key shape: {G_pub.dimensions()}")

c_bits = hex_to_bits(c_hex)
print(f"Total ciphertext bits: {len(c_bits)}")

# Split into blocks of size N
c_bits_blocks = pad_bits_to_blocks(c_bits, N)
print(f"Number of blocks: {len(c_bits_blocks)}")

# Store all decrypted message bits
all_message_bits = []

for block_idx, c_block in enumerate(c_bits_blocks):
    print(f"\n--- Processing block {block_idx + 1}/{len(c_bits_blocks)} ---")
    
    c_vector = vector(GF(2), c_block)
    
    for error_pos in range(N):
        try:
            c_corrected = c_vector[:]
            c_corrected[error_pos] = c_corrected[error_pos] + 1  # Flip bit in GF(2)
            
            m_solution = G_pub.solve_left(c_corrected)
            m_bits = [int(x) for x in m_solution]
            
            encoded = vector(GF(2), m_bits) * G_pub
            if encoded == c_corrected:
                msg_bytes = bits_to_bytes(m_bits)
                try:
                    text = msg_bytes.decode('utf-8', errors='replace')
                    print(f"Error pos {error_pos:2d}: {text.encode('unicode_escape').decode()}")
                except:
                    print(f"Error pos {error_pos:2d}: {msg_bytes}")
                
                all_message_bits.append((block_idx, error_pos, m_bits, msg_bytes, text))
                
        except Exception as e:
            continue

print("\n" + "="*60)
print("SUMMARY OF ALL CANDIDATES:")
print("="*60)

for block_idx in range(len(c_bits_blocks)):
    block_candidates = [x for x in all_message_bits if x[0] == block_idx]
    if block_candidates:
        print(f"\nBlock {block_idx + 1} candidates:")
        for _, error_pos, m_bits, msg_bytes, text in block_candidates:
            print(f"  Error pos {error_pos:2d}: '{text}' | {msg_bytes}")

print("\n" + "="*60)
print("ATTEMPTING TO RECONSTRUCT FULL MESSAGE:")
print("="*60)

best_candidates = []
for block_idx in range(len(c_bits_blocks)):
    block_candidates = [x for x in all_message_bits if x[0] == block_idx]
    
    if not block_candidates:
        print(f"Block {block_idx + 1}: No valid candidates")
        continue
    
    best_candidate = None
    best_score = -1
    
    for candidate in block_candidates:
        _, error_pos, m_bits, msg_bytes, text = candidate
        
        printable_count = sum(1 for c in text if c.isprintable() and ord(c) < 127)
        score = printable_count / len(text) if len(text) > 0 else 0
        
        common_chars = sum(1 for c in text.lower() if c in 'etaoinshrdlucmfwypvbgkjqxz ')
        score += common_chars / len(text) * 0.5 if len(text) > 0 else 0
        
        if score > best_score:
            best_score = score
            best_candidate = candidate
    
    if best_candidate:
        _, error_pos, m_bits, msg_bytes, text = best_candidate
        print(f"Block {block_idx + 1}: Error pos {error_pos}, Score {best_score:.2f}: '{text}'")
        best_candidates.append(m_bits)
    else:
        print(f"Block {block_idx + 1}: No good candidate found")

if best_candidates:
    print("\n" + "="*60)
    print("RECONSTRUCTED MESSAGE:")
    print("="*60)
    
    full_message_bits = []
    for bits in best_candidates:
        full_message_bits.extend(bits)
    
    full_bytes = bits_to_bytes(full_message_bits)
    
    text = full_bytes.decode('utf-8', errors='replace')
    
    print(f"Raw combined text: '{text}'")
    print(f"Raw bytes: {full_bytes}")
    
    clean_text = ""
    for char in text:
        if char.isprintable() and ord(char) < 127:
            clean_text += char
        elif char == '\x01':
            break
    
    print(f"Cleaned text: '{clean_text}'")
    
    print("\nBlock-by-block interpretation:")
    for i, bits in enumerate(best_candidates):
        block_bytes = bits_to_bytes(bits)
        block_text = block_bytes.decode('utf-8', errors='replace')

        clean_block = ""
        for char in block_text:
            if char.isprintable() and ord(char) < 127:
                clean_block += char
            elif char == '\x01':
                break
        print(f"  Block {i+1}: '{clean_block}'")
else:
    print("Could not reconstruct message - no valid candidates found")