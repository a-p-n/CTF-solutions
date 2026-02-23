import dill
import numpy as np
import hashlib
from itertools import cycle

def solve():
    print("[*] Loading model.dill...")
    try:
        with open("model.dill", "rb") as f:
            data = dill.load(f)
    except Exception as e:
        print(f"[-] Error loading file: {e}")
        return

    # Extract the Model Components
    # The file contains a dictionary with the model and the hidden function
    model = data.get('model')
    
    # We don't need to execute 'evil_intern_shenanigans', we just use its logic.
    tree = model.tree_
    children_left = tree.children_left
    children_right = tree.children_right
    values = tree.value
    classes = model.classes_

    print("[*] Traversing tree and decrypting flag...")

    # --- The Reconstructed Decryption Logic ---
    def intern_decrypt(hex_value, path_str):
        # 1. Convert the path string (e.g., "0101") into a numpy array of bits
        path_bits = [int(c) for c in path_str]
        
        # 2. Pack these bits into bytes (matching the 'packbits' we saw in analysis)
        #    Note: we must use uint8 to ensure correct byte packing
        arr = np.array(path_bits, dtype=np.uint8)
        path_bytes = np.packbits(arr).tobytes()
        
        # 3. Generate the Key: SHA256 Hash of the path
        key = hashlib.sha256(path_bytes).digest()
        
        # 4. XOR the Hex Value with the Key
        cipher_bytes = bytes.fromhex(hex_value)
        
        decrypted = bytearray()
        # Cycle the key in case the cipher text is longer than 32 bytes
        for b, k in zip(cipher_bytes, cycle(key)):
            decrypted.append(b ^ k)
            
        return decrypted.decode('utf-8', errors='ignore')

    # --- Tree Traversal (Depth First Search) ---
    decrypted_fragments = []

    def visit(node_id, path):
        # If the left child is -1, it is a Leaf Node
        if children_left[node_id] == -1:
            # Get the Hex String associated with this leaf
            # (The tree stores the class index, we map it to the hex string)
            class_idx = np.argmax(values[node_id])
            hex_value = classes[class_idx]
            
            # Decrypt this segment using the current path
            try:
                fragment = intern_decrypt(hex_value, path)
                # Only keep fragments that look like text (filter out empty/garbage)
                if fragment:
                    decrypted_fragments.append(fragment)
            except Exception:
                pass
            return

        # Recurse Left (Append '0')
        visit(children_left[node_id], path + "0")
        
        # Recurse Right (Append '1')
        visit(children_right[node_id], path + "1")

    # Start the walk from the Root (Node 0)
    visit(0, "")

    # Join all fragments to reveal the flag
    full_output = "".join(decrypted_fragments)
    
    print("-" * 50)
    print("FLAG RESULT:")
    print(full_output)
    print("-" * 50)

if __name__ == "__main__":
    solve()
