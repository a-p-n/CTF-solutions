from pwn import *

def main():
    conn = remote('s1.r3.ret.sh.cn',31856)
    
    conn.recvuntil(b'number! ')
    g, g_1, g_2, h_2, u_2, pair_of_g_g, pair_of_g_2_g = eval(conn.recvline().decode().strip())
    conn.recvuntil(b'> ')
    
    conn.sendline(b'4')
    output = conn.recvuntil(b'END').decode()
    
    target_index = 3
    
    blocks = output.split('HP:')
    r_data = blocks[0].split('R:')[1].split('L:')[0].strip()
    r_parts = r_data.strip()
    r0 = r_parts[0].strip("'")
    r1 = r_parts[1].strip("'")
    r2 = r_parts[2].strip("'")
    
    conn.sendline(b'5')
    conn.recvuntil(b'Index> ')
    conn.sendline(str(0).encode())
    conn.recvuntil(b'Message> ')
    conn.sendline(b'Selling|flag|100')
    conn.recvuntil(b'Randomness> ')
    conn.sendline(r_parts.encode())
    conn.recvuntil(b'> ')
    
    for _ in range(20):
        conn.sendline(b'1')
        conn.recvuntil(b'> ')

    conn.sendline(b'2')
    conn.recvuntil(b'> ')
    
    conn.sendline(b'6')
    result = conn.recvall().decode()
    
    if 'Buy flag' in result:
        flag_line = [line for line in result.split('\n') if 'Buy flag' in line][0]
        flag = flag_line.split('Buy flag, ')[1].split(',')[0]
        print(f"Flag: {flag}")
    else:
        print("Flag not found. Output:")
        print(result)

if __name__ == "__main__":
    main()