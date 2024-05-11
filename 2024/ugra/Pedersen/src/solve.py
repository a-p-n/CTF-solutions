#!/usr/bin/env python3
from base64 import b64decode, b64encode
import json
import requests
from icecream import ic

BASE = "https://pedersen.q.2024.ugractf.ru/x27r8ayzu8n1zara"

def issue():
    return json.loads(b64decode(requests.get(f"{BASE}/issue").text).decode())

def submit(data):
    print("sending ==>", data)
    url = f"{BASE}/checkout?wallet={b64encode(json.dumps(data).encode()).decode()}"
    # print("url ==>", url)
    return requests.get(url).text

tok1 = issue()
tok2 = issue()
tok3 = {}
tok3['commitment'] = hex(int(tok1['commitment'],16)*4)[2:]
tok3['blinding'] = hex(int(tok1['blinding'],16)*4)[2:]
tok3['balance'] = 400
print(submit(tok3))