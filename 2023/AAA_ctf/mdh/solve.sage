from hashlib import sha256
r = 128
c = 96
p = 308955606868885551120230861462612873078105583047156930179459717798715109629
Fp = GF(p)
f = open('/home/apn/Documents/bi0s/my_git/Crypto/ctf/AAA_ctf/mdh/output.txt')
ct = eval(f.readline())
A = matrix(Fp, eval(f.readline()))
B = matrix(Fp, eval(f.readline()))

shared = (A.T * B).trace()
flag = int(sha256(str(int(shared)).encode()).hexdigest(), 16) ^^ ct
print(bytes.fromhex(hex(flag)[2:]).decode())
