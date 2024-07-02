import os
from itertools import combinations

MIN_X = 600
MAX_X = 1000
MIN_Y = 400
MAX_Y = 800

DECRYPTED_FILE = "all_flags.enc"

def add_ppm_header(file_path, x, y):
    header = f"P6\n{x} {y}\n65535\n".encode()
    with open(file_path, "rb") as file:
        data = file.read()
    with open(f"{file_path}.ppm", "wb") as output_file:
        output_file.write(header + data)

def brute_force_dimensions():
    for x, y in product(range(MIN_X, MAX_X + 1), range(MIN_Y, MAX_Y + 1)):
        split_size = x * y * 3
        split_files = []
        with open(DECRYPTED_FILE, "rb") as file:
            data = file.read()
            for i in range(0, len(data), split_size):
                split_file = f"flag_{i // split_size}"
                with open(split_file, "wb") as split_file_obj:
                    split_file_obj.write(data[i:i + split_size])
                split_files.append(split_file)

        for split_file in split_files:
            if not split_file.endswith(".ppm"):
                add_ppm_header(split_file, x, y)
                os.remove(split_file)

if __name__ == "__main__":
    brute_force_dimensions()