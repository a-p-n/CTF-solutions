  [2/2]                                                                                                      streamer/output.py                                                                                                               
import secrets
import hashlib
import base64
import re


cipher = [163, 227, 86, 67, 200, 14, 176, 188, 101, 214, 117, 82, 99, 71, 199, 117, 139, 130, 78, 43, 224, 101, 183, 219, 82, 213, 70, 95, 101, 118, 133, 46, 146, 239, 98, 97, 250, 123, 183, 218, 82, 218, 1, 97, 62, 29, 145, 105, 168, 13>
flag_length = 304

flag = b"TSGCTF{"
key = []
for i in range(4):
	key.append(cipher[i]^flag[i])

for i in range(0,len(cipher),16):
	
