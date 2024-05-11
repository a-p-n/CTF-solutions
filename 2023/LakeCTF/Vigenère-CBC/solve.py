SHIFT = 65
MOD = 26
BLOCKLENGTH = 20
BLOCKSIZE = 20

ct = 'AFCNUUOCGIFIDTRSBHAXVHZDRIEZMKTRPSSXIBXCFVVNGRSCZJLZFXBEMYSLUTKWGVVGBJJQDUOXPWOFWUDHYJSMUYMCXLXIWEBGYAGSTYMLPCJEOBPBOYKLRDOJMHQACLHPAENFBLPABTHFPXSQVAFADEZRXYOXQTKUFKMSHTIEWYAVGWWKKQHHBKTMRRAGCDNJOUGBYPOYQQNGLQCITTFCDCDOTDKAXFDBVTLOTXRKFDNAJCRLFJMLQZJSVWQBFPGRAEKAQFUYGXFJAWFHICQODDTLGSOASIWSCPUUHNLAXMNHZOVUJTEIEEJHWPNTZZKXYSMNZOYOVIMUUNXJFHHOVGPDURSONLLUDFAGYGWZNKYXAGUEEEGNMNKTVFYZDIQZPJKXGYUQWFPWYEYFWZKUYUTXSECJWQSTDDVVLIYXEYCZHYEXFOBVQWNHUFHHZBAKHOHQJAKXACNODTQJTGC'
assert len(ct) == 471

def add(block1,block2):
    assert(len(block1)<= len(block2))
    assert(len(block2)<= BLOCKLENGTH)
    b1upper = block1.upper()
    b2upper = block2.upper()
    b1 = [ ord(b1upper[i])-SHIFT for i in range(len(block1))]
    b2 = [ ord(b2upper[i])-SHIFT for i in range(len(block1))]
    s = [ (b1[i] + b2[i]) % MOD for i in range(len(block1))]
    slist = [ chr(s[i]+SHIFT) for i in range(len(block1))]
    sum = ''.join(slist)
    return(sum)

def sub(block1,block2):
    assert(len(block1)<= len(block2))
    assert(len(block2)<= BLOCKLENGTH)
    b1upper = block1.upper()
    b2upper = block2.upper()
    b1 = [ ord(b1upper[i])-SHIFT for i in range(len(block1))]
    b2 = [ ord(b2upper[i])-SHIFT for i in range(len(block1))]
    s = [ (b1[i] - b2[i]) % MOD for i in range(len(block1))]
    slist = [ chr(s[i]+SHIFT) for i in range(len(block1))]
    sum = ''.join(slist)
    return(sum)

blocks = [ct[i:i+BLOCKSIZE] for i in range(0,len(ct),BLOCKSIZE)]
diffs = [sub(blocks[i+1],blocks[i]) for i in range(len(blocks)-1)]
print(''.join(diffs))

# This gives an output, put that into dcode.fr and it gives you that plaintext