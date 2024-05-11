from pwn import *
import random as rd 

responses = [
    b'Nothing happened',
    b'Sorry you hit',
    b'It seems you'
]
opposite_directions ={
    "S" : "W",
    "A" : "D",
    "D" : "A",
    "W" : "S"
}
#! north(W), south(S), east(D) and west(A) 
directions = [b'W', b'D', b'S', b'A'] 
io = remote("202.112.238.82",13370)
a = io.recv(0x1000)
print(a)
trap_flag = False 
keep_track = list()
io.sendline(directions[0])
print(io.recv(0x1000))
prev_mov = None 

while 1:
    input = rd.randint(0, len(directions ) -1 )
    next_mov = directions[input]
    if trap_flag and next_mov == prev_mov: continue
    io.sendline(next_mov)
    trap_flag = False 
    keep_track.append(directions[input])
    output = (io.recv(0x1000))
    # print(output)
    prev_mov = directions[input] ## Tracking prev pos
    if responses[1] in output: 
        trap_flag = True 
        next_mov = opposite_directions.get(prev_mov)
    if b"flag fragment" in a :
        print(input, output)
        # with open("/home/apn/Documents/bi0s/my_git/Crypto/ctf/tp/nanouniverse/movements.txt","+a") as f:
        #     f.(str(keep_track))
