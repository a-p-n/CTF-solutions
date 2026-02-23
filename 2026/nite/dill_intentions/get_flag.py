import dill
import numpy as np
import hashlib
from itertools import cycle
import string

def solve():
    print("[*] Loading model.dill...")
    try:
        with open("model.dill", "rb") as f:
            data = dill.load(f)
    except Exception as e:
        print(f"[-] Error loading file: {e}")
        return

    model = data.get('model')
    debug_func = data.get('decision_path_for_debugging')
    
    # --- Decryption Logic ---
    def intern_decrypt(hex_value, path_str):
        try:
            path_bits = [int(c) for c in path_str]
            arr = np.array(path_bits, dtype=np.uint8)
            path_bytes = np.packbits(arr).tobytes()
            key = hashlib.sha256(path_bytes).digest()
            cipher_bytes = bytes.fromhex(hex_value)
            decrypted = bytearray()
            for b, k in zip(cipher_bytes, cycle(key)):
                decrypted.append(b ^ k)
            return decrypted
        except:
            return b""

    # --- Tree Analysis ---
    tree = model.tree_
    children_left = tree.children_left
    children_right = tree.children_right
    values = tree.value
    classes = model.classes_
    
    print("[*] Scanning leaves to find the 'Garbage' node (The Flag)...")
    
    # We define "Garbage" as having many non-printable characters.
    # Normal diagnoses like "uterine cancer" are all printable.
    printable_chars = set(string.printable.encode('ascii'))
    
    target_node_id = -1
    target_hex = ""

    # DFS to check every leaf
    stack = [(0, "")]  # (node_id, path_str)
    
    while stack:
        node_id, path = stack.pop()
        
        # If Leaf
        if children_left[node_id] == -1:
            class_idx = np.argmax(values[node_id])
            hex_val = classes[class_idx]
            
            # Decrypt with Standard Path
            decrypted = intern_decrypt(hex_val, path)
            
            # Check if it looks like garbage (Flag encrypted with wrong key)
            non_printable_count = sum(1 for b in decrypted if b not in printable_chars)
            
            # If more than 30% are non-printable, this is likely our target
            if len(decrypted) > 0 and (non_printable_count / len(decrypted)) > 0.3:
                print(f"[!] FOUND SUSPICIOUS NODE: ID {node_id}")
                print(f"    Standard Decrypt (Garbage): {decrypted[:20]}...")
                target_node_id = node_id
                target_hex = hex_val
                break
        else:
            # Push children (Right first so Left is processed first)
            if children_right[node_id] != -1:
                stack.append((children_right[node_id], path + "1"))
            if children_left[node_id] != -1:
                stack.append((children_left[node_id], path + "0"))

    if target_node_id == -1:
        print("[-] Could not identify a garbage node. Check logic.")
        return

    # --- Retrieve the Magic Path ---
    print(f"[*] Attempting to retrieve magic key for Node {target_node_id}...")
    magic_path = None
    
    try:
        # Try calling with (self, node_id) -> (None, node_id)
        magic_path = debug_func(None, target_node_id)
        print(f"[+] Debug function returned: {magic_path}")
    except TypeError:
        try:
            # Fallback: Try just (node_id) again (unlikely based on logs)
            magic_path = debug_func(target_node_id)
        except Exception as e:
            print(f"[-] Debug function failed: {e}")
            
    if magic_path:
        print("[*] Decrypting with Magic Path...")
        flag = intern_decrypt(target_hex, magic_path)
        print("\n" + "="*50)
        try:
            print(f"FLAG: {flag.decode('utf-8')}")
        except:
            print(f"FLAG (Raw): {flag}")
        print("="*50)
    else:
        print("[-] Could not get magic path.")

if __name__ == "__main__":
    solve()
