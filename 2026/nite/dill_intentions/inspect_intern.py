import dill
import numpy as np

def inspect():
    print("[*] Loading model.dill...")
    with open("model.dill", "rb") as f:
        data = dill.load(f)

    # 1. Inspect the suspicious 'evil_intern_shenanigans' key
    if 'evil_intern_shenanigans' in data:
        shenanigans = data['evil_intern_shenanigans']
        print(f"\n[!] Found 'evil_intern_shenanigans' (Type: {type(shenanigans)}):")
        print(f"    Value: {repr(shenanigans)}")
    
    # 2. Inspect 'decision_path_for_debugging'
    if 'decision_path_for_debugging' in data:
        debug_path = data['decision_path_for_debugging']
        print(f"\n[!] Found 'decision_path_for_debugging' (Type: {type(debug_path)}):")
        # Print first 100 chars if it's a long list/string
        print(f"    Value: {repr(debug_path)[:200]}...")

    # 3. Debug the Tree Thresholds (Why was it empty?)
    model = data.get('model')
    if hasattr(model, "tree_"):
        print(f"\n[+] Tree Threshold Sample (First 20):")
        # Print raw floats to see if they are ASCII-like (e.g. 102.0) or encoded
        print(model.tree_.threshold[:20])
        
        # Check the 'value' array (another common hiding spot)
        print(f"\n[+] Tree Values Sample (First 5 nodes):")
        print(model.tree_.value[:5])
        
        # Check classes
        if hasattr(model, "classes_"):
            print(f"\n[+] Model Classes: {model.classes_}")

if __name__ == "__main__":
    inspect()
