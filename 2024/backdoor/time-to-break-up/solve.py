import base64
from pwn import *

text_messages_2 = [
    "Alice? Where have you been? Are you ok?",
    "Hi Bob. I've just been at home. Didn't want to go to work. ",
    "You should have come with us last night. It was so fun.",
    "Oh, I see. Was Eve There?",
    "Yeah. What's wrong babe? You seem a bit down in the dumps.",
    "Nothing. There's just been a lot on my mind.",
    "Is everything alright?",
    "I'm fine. You don't have to worry about me.",
    "Let's go out tonight. We could go eat, dance and later stay together at night. It'll freshen you up.",
    "Hmm.. Sure, I'd love that. Thank you Bob.",
    "Yay! I'll come pick you up at 5. Be Ready!"
]

def serialise(x):
    return base64.b64encode(x).decode()

def deserialise(x):
    return base64.b64decode(x.encode())

def pad(x):
    return x + b"\x00"*((-len(x))%16)

def xorbytes(a,b):
    res = bytes([i^j for i,j in zip(a,b)])
    if len(a)>len(b):
        res+=a[len(b):]
    return res

io = remote('34.42.147.172', 8002)

print("PART 1:")
for _ in range(2):
    io.recvuntil(b'(yes/no) :')
    io.sendline(b'yes')

val = io.recvuntil(b"plaintext recieved : Well Enough, just got home darling. So much drama at the office. Charlie has been spreading rumors that you're cheating with Eve.\n")

io.recvuntil(b"ciphertext recieved : ")
ciph1 = io.recvline().strip(b"\n").decode()
ciph1 = serialise(pad(deserialise(ciph1)[:64]))

io.recvuntil(b"Go ahead. Cut that text in half. Don't let Bob know about this rumor.\n\n")
io.sendline(ciph1.encode())

io.recvuntil(b'Bob\'s Message : "Who, me? Nothing, just hanging out at the bar with some friends."\n')
io.recvuntil(b"Bob's Ciphertext : ")

ptext = b"Who, me? Nothing, just hanging out at the bar with some friends."
ciph = io.recvline().decode().strip("\n")
ciph = deserialise(ciph)

n = xor(ciph[-32:-16],ptext[-16:])
newciph = xor(n,b" Eve is so cute.")

val = serialise(newciph + ciph[-16:])

io.recvuntil(b'Add corrpution to ciphertext : \n')
io.sendline(val.encode())

io.recvuntil(b"Send Text? (y/n) : ")
io.sendline(b"y")

io.recvuntil(b'First part of flag : ')
flag1 = io.recvline()
print(flag1.decode())

print("PART 2:",end=" ")
ppl = ["Bob","Alice"]
streams = []

for i in range(11):     
    print(i,end="")         
    res = f"{ppl[i%2]}'s Length of message : ".encode()
    io.recvuntil(res)
    length = int(io.recvline().decode().strip("\n"))
    io.recvuntil(f'What length do you want to send forward to {ppl[(i+1)%2]} : '.encode())

    if i%2==1 and i<9:
        length += 32

    pt = pad(text_messages_2[i].encode())

    io.sendline(str(length).encode())
    io.recvuntil(f'{ppl[(i+1)%2]} sending encrypted salt : '.encode())
    salt = io.recvline().decode().strip("\n")
    io.sendline(salt.encode())
    
    if i%2==1:
        io.recvuntil(f'Sending final ciphertext to {ppl[(i+1)%2]} : '.encode())
        final_ct = deserialise(io.recvline().decode().strip('\n'))
        io.recvuntil(b'Leaked xorkey : ')
        xorkey = deserialise(io.recvline().decode().strip('\n'))

        keystream = xor(final_ct,pt,xorkey)
        streams.append(keystream)

    if i==10:
        keystream = streams[-1]
        
        io.recvuntil(b'Leaked xorkey : ')
        xorkey = deserialise(io.recvline().decode().strip("\n"))
        pt = "Noice! Let me ask Eve if she would like to come.".encode()
        final_ct = serialise(xor(xorkey,keystream,pt))

        io.recvuntil(b'The message should read "Noice! Let me ask Eve if she would like to come."\n')
        io.sendline(final_ct.encode())

        io.recvuntil(b'Third part of flag : ')
        flag3 = io.recvline().decode().strip("\n")
        print("\n",flag3,sep="")
    
splitted = []
for stream in streams:
    for i in range(len(stream)//16):
        splitted.append(stream[16*i:16+16*i])
print(splitted) #23 blocks as individual elements
io.interactive()