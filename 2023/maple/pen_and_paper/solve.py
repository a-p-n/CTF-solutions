from string import ascii_uppercase as ALPHABET

with open("ciphertext.txt","r") as f:
    a = (f.read())

l = ""
for i in a:
    if i in ALPHABET:
        l += i

c = [l[:13]]
for i in range(13,len(l),13):
    c.append(l[i:13+i])
    # c.append(l[-i//13:]+l[i:-i//13])

for i in range(1,len(c)):
    c[i] = c[i][-i:] + c[i][:-i]
print(c)
IND1,IND2,IND3,IND4 = [],[],[],[]
for i in range(len(a)):
    if a[i] == " ":
        IND1.append(i)
    elif a[i] == ",":
        IND2.append(i)
    elif a[i] == ".":
        IND3.append(i)
    elif a[i] == "\n":
        IND4.append(i)
    
# print(a)
# ind = 1
# for i in range(len(c)):
#     if " " in a[13*(ind-1):13*ind]:
#         ind2 = a[13*(ind-1):13*ind].find(" ")
#         c[i] = c[i][:ind2]+" "+c[i][ind2:]
#     elif "." in a[13*(ind-1):13*ind]:
#         ind2 = a[13*(ind-1):13*ind].find(" ")
#         c[i] = c[i][:ind2]+"."+c[i][ind2:]
#     elif "," in a[13*(ind-1):13*ind]:
#         ind2 = a[13*(ind-1):13*ind].find(" ")
#         c[i] = c[i][:ind2]+","+c[i][ind2:]
#     elif "\n" in a[13*(ind-1):13*ind]:
#         ind2 = a[13*(ind-1):13*ind].find(" ")
#         c[i] = c[i][:ind2]+"\n"+c[i][ind2:]
#     ind+=1

open("plaintext","w").write("".join(i for i in c))

d = {"E" : 12.7 , "T" : 9.06 , "A" : 8.17 , "O" : 7.51 , "I" : 6.97 , "N" : 6.75 , "S" : 6.33 , "H" : 6.09 , "R" : 5.99 , "D" : 4.25 , "L" : 4.03 , "C" : 2.78 , "U" : 2.76 , "M" : 2.41 , "W" : 2.36
     ,"F" : 2.23 , "G" : 2.02 , "Y" : 1.97 , "P" : 1.93 , "B" : 1.29 , "V" : 0.98 , "K" : 0.77 , "J" : 0.15 , "X" : 0.15 , "Q" : 0.10 , "Z" : 0.07}