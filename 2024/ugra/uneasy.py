from PIL import Image
from base64 import b64decode as bd
from pix2tex.cli import LatexOCR
from latex2sympy2 import latex2sympy
import requests
import json
import base64
import io

def get_image():
    url = 'https://peterparker2.q.2024.ugractf.ru/3a31ljjfgq4jj2dj/'
    myobj = {"Content-Type": "application/json"}
    txt = (requests.post(url, json=myobj)).text
    b64img = json.loads(txt)["picture"].split(",")[1]
    return base64.b64decode(b64img)

def send_res(ans):
    url = 'https://peterparker2.q.2024.ugractf.ru/3a31ljjfgq4jj2dj/'
    header = {"Content-Type": "application/json"}
    myobj = {"captcha_response": ans} if ans == 0 else {}
    x = requests.post(url, headers=header, json=myobj)
    resp = json.loads(x.text)
    return resp

def do_math(img):
    model = LatexOCR()
    tex = model(img)
    # print(tex)
    symt = latex2sympy(tex)
    print(symt)
    res = symt.evalf()
    print(res)
    return res

def main():
    img = get_image()
    cvimg = Image.open(img)
    mres = do_math(cvimg)
    ans = round(mres, 3)
    print(ans)
    res = send_res(ans)
    print(res)

main()