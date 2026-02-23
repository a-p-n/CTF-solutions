import dill
import numpy as np

def solve():
    print("[*] Loading model.dill...")
    try:
        with open("model.dill", "rb") as f:
            data = dill.load(f)
    except Exception as e:
        print(f"[-] Error loading file: {e}")
        return

    # 1. Analyze the Evil Function (Static Analysis)
    if 'evil_intern_shenanigans' in data:
        func = data['evil_intern_shenanigans']
        code = func.__code__
        
        print("\n[+] --- FUNCTION ANALYSIS ---")
        print(f"Constants (co_consts): {code.co_consts}")
        print(f"Names (co_names): {code.co_names}")
        print(f"Varnames (co_varnames): {code.co_varnames}")
        # This will likely reveal a constant integer or string used for XOR

    # 2. Extract Hex Strings in Tree Order (DFS)
    # The flag is almost certainly scattered across the leaves in order.
    model = data.get('model')
    tree = model.tree_
    children_left = tree.children_left
    children_right = tree.children_right
    values = tree.value
    classes = model.classes_

    print("\n[+] --- TREE TRAVERSAL (DFS) ---")
    
    leaf_data = []

    def visit(node_id, path):
        # Leaf Node
        if children_left[node_id] == -1:
            class_idx = np.argmax(values[node_id])
            hex_value = classes[class_idx]
            leaf_data.append((path, hex_value))
            return

        visit(children_left[node_id], path + "0")
        visit(children_right[node_id], path + "1")

    visit(0, "")

    print(f"Collected {len(leaf_data)} leaf segments.")
    
    # 3. Attempt Decryption (Heuristic)
    # If the function does: Hex XOR Path, let's try it here in safe Python.
    print("\n[+] --- ATTEMPTING DECRYPTION ---")
    
    flag_chars = []
    
    for path, hex_str in leaf_data:
        try:
            # Convert hex to bytes
            data_bytes = bytes.fromhex(hex_str)
            
            # Heuristic 1: Is it just the hex decoded?
            # flag_chars.append(data_bytes.decode('utf-8')) # Unlikely to be this simple
            
            # Heuristic 2: XOR with the path?
            # The path is a string "01010", data is bytes.
            # Common CTF trick: XOR key is the path string or bits.
            
            # Try XORing the first byte of data with the first char of path?
            # Or assume the function uses a simple XOR with a constant found in step 1.
            # Let's start by just collecting the RAW HEX to look for patterns.
            pass
        except:
            pass
            
    # Print the first few raw hex entries to inspect manually
    print("First 5 Leaf Hex Values:")
    for i in range(5):
        print(f"Path: {leaf_data[i][0]} | Hex: {leaf_data[i][1]}")

if __name__ == "__main__":
    solve()
