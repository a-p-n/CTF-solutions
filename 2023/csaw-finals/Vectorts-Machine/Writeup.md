# Vector's Machine

## Premise

- Challenge is based on **Linear Support Vector Machine** (SVM) which is an algorithm in Machine Learning.
- Used to **linearly separate data** - a dataset can be classified into two classes by using a single straight line.
- We are given nc. We need to input the x-axis and y-axis and it will return whether the point is cool or not. Basically, it returns whether the point is on the left or right side of the line.

## Exploit

- Take 2 points on the x-axis: 1 Cool and 1 Not Cool.
- Then take the **mid point** of the both of the points and then check whether the point is cool or not. 
    1. If the point is cool then take the mid point of this point and the Not Cool point.
    2. If the point is not cool then take the mid point of this point and the cool point.
- Go on like that until the first 4 decimal places of the points remain constant.
We will get the **y-intercept** of the line.
- Then take 2 points on y-axis : 1 Cool and 1 Not Cool and do the same procedure as given above.
We will get **x-intercept** of the line .
- To find the **slope** use the formula **s = -y/x**
- Take slope and y-intercept and then combine them together and then remove the decimal points.
- Take two digits from it one by one and then convert it into chr.

```py
def cool_uncool(p):
    return p
def bs(p1,p2):
    mp = ((p2[0] - p1[0])/2,(p2[1] - p1[1]))
    if round(mp.4) == round(p1,4) or round(mp.4) == round(p2,4):
        return mp
    if "not cool" in cool_uncool(mp):
        bs(mp,p2)
    else:
        bs(p1,mp)
POINTS = [(0,-80488255.51680756), (1,-158976709.37480164)]
slope = round((POINTS[1][1] - POINTS[0][1])/(POINTS[1][0] - POINTS[0][0]),4)
# slope = -78488453.8580
y-intercept = round(POINTS[0][1] - m*POINTS[0][0],4)
# y-intercept = -80488255.5168

enc_flag = "784884538580804882555168"
for i in range(0,len(enc_flag),2):
    print(chr(int(enc_flag[i:i+2])),end = "")

# N0T5UPP0R73D
FLAG = "csawctf{N0T5UPP0R73D}"
```