import requests
from bs4 import BeautifulSoup
from mt19937predictor import MT19937Predictor

url = 'http://184.72.87.9:8001'
nums = requests.get(url + '/winning_numbers')
bs = BeautifulSoup(nums.text, 'html.parser')

endpoints = bs.text.splitlines()[8:13+8:][::-1]
print(endpoints)

nums = []
for endpoint in endpoints:
    bs = BeautifulSoup(requests.get(url+f'/winning_numbers?timestamp={endpoint}').text, 'html.parser')
    nums.extend(list(map(int, bs.text.splitlines()[8:-2])))
    print(endpoint)

print(nums)
predictor = MT19937Predictor()
for num in nums:
    predictor.setrandbits(num, 32)

for i in range(48):
    print(predictor.getrandbits(32))