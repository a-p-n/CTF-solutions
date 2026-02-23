from pwn import *
import hashpumpy
import re

# Configuration
HOST = 'vegas.chals.nitectf25.live'
PORT = 1337
USERNAME = b"hacker"

def solve():
    # Loop until we get the flag (handling the 1/2048 probability)
    while True:
        try:
            # Connect with SSL
            r = remote(HOST, PORT, ssl=True, level='error')
            
            # 1. Login
            r.recvuntil(b'username: ')
            r.sendline(USERNAME)
            
            # 2. Get the first winning ticket (The "Funding Voucher")
            print("[*] Attempting to get initial funding voucher...")
            funding_voucher = None
            
            # Try to buy a ticket. If we lose (balance=0), we must reconnect.
            r.recvuntil(b'choice: ')
            r.sendline(b'3') # Buy Ticket
            r.recvuntil(b'odds): ')
            r.sendline(b'1') # Pay $1
            
            response = r.recvuntil(b'choice: ', drop=True).decode()
            
            if "You lost!" in response:
                print("[-] Lost initial ticket. Retrying connection...")
                r.close()
                continue # Restart loop
            
            # Parse the voucher details
            print("[+] Won initial ticket! Saving voucher.")
            voucher_data_match = re.search(r'Voucher data:\s+([0-9a-f]+)', response)
            voucher_code_match = re.search(r'Voucher code:\s+([0-9a-f]+)', response)
            
            if not voucher_data_match or not voucher_code_match:
                print("[-] Error parsing voucher.")
                r.close()
                continue
                
            funding_data_hex = voucher_data_match.group(1)
            funding_code_hex = voucher_code_match.group(1)
            
            # 3. Brute Force Loop
            # We use the funding voucher to buy tickets until we hit a SHA1 signature
            attempts = 0
            while True:
                attempts += 1
                if attempts % 100 == 0:
                    print(f"[*] Attempt {attempts}...")

                # A. Fund the account using Replay Attack
                r.sendline(b'4') # Redeem Voucher
                r.recvuntil(b'code(hex): ')
                r.sendline(funding_code_hex.encode())
                r.recvuntil(b'data(hex): ')
                r.sendline(funding_data_hex.encode())
                r.recvuntil(b'choice: ')
                
                # B. Buy a new ticket
                r.sendline(b'3') # Buy Ticket
                r.recvuntil(b'odds): ')
                r.sendline(b'1') # Pay $1
                result = r.recvuntil(b'choice: ', drop=True).decode()
                
                # If we lost the lottery, just loop back and fund again
                if "You lost!" in result:
                    continue
                
                # If we won, we have a candidate for LEA
                v_data_hex = re.search(r'Voucher data:\s+([0-9a-f]+)', result).group(1)
                v_code_hex = re.search(r'Voucher code:\s+([0-9a-f]+)', result).group(1)
                
                # C. Attempt Length Extension Attack (Assuming SHA1)
                # Key length is 32 (from os.urandom(16).hex() which creates a 32-char string)
                # We append |1000000000 to overwrite the amount
                
                original_data = bytes.fromhex(v_data_hex)
                append_data = b"|1000000000"
                
                new_hash, new_data = hashpumpy.hashpump(
                    v_code_hex,       # Original Signature
                    original_data,    # Original Data
                    append_data,      # Data to append
                    32                # Key length (32 bytes)
                )
                
                new_data_hex = new_data.hex()
                
                # D. Try to redeem the forged voucher
                r.sendline(b'4')
                r.recvuntil(b'code(hex): ')
                r.sendline(new_hash.encode())
                r.recvuntil(b'data(hex): ')
                r.sendline(new_data_hex.encode())
                
                redeem_res = r.recvuntil(b'choice: ', drop=True).decode()
                
                if "Voucher redeemed" in redeem_res:
                    # Check balance to see if it worked
                    r.sendline(b'5') # Get Balance
                    bal_res = r.recvuntil(b'choice: ', drop=True).decode()
                    if "100000000" in bal_res: # Check for high balance
                        print("[+] LEA SUCCESS! Balance is huge.")
                        
                        # Get Flag
                        r.sendline(b'6')
                        flag_res = r.recvuntil(b'}').decode()
                        print("\n" + "="*40)
                        print(flag_res)
                        print("="*40 + "\n")
                        return
                    else:
                        # It was a valid hash (maybe we hit SHA1?) but logic failed?
                        # Or we just redeemed the original amount?
                        pass
                else:
                    # "Invalid voucher" - likely meant the original hash wasn't SHA1
                    pass

        except Exception as e:
            print(f"[-] Disconnected or error: {e}")
            # Reconnect loop will catch this

if __name__ == "__main__":
    solve()