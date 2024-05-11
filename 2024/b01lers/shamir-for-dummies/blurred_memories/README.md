# Writeup

This was the code we were given for this challenge: 
```py
from secret import flag

assert flag[:6] == 'TPCTF{' and flag[-1] == '}'
flag = flag[6:-1]

assert len(set(flag)) == len(flag)

xs = []
for i, c in enumerate(flag):
    xs += [ord(c)] * (i + 1)

p = 257
print('output =', [sum(pow(x, k, p) for x in xs) % p for k in range(1, len(xs) + 1)])

```

And the output is as follows:
```
output = [125, 31, 116, 106, 193, 7, 38, 194, 186, 33, 180, 189, 53, 126, 134, 237, 123, 65, 179, 196, 99, 74, 101, 153, 84, 74, 233, 5, 105, 32, 75, 168, 161, 2, 147, 18, 68, 68, 162, 21, 94, 194, 249, 179, 24, 60, 71, 12, 40, 198, 79, 92, 44, 72, 189, 236, 244, 151, 56, 93, 195, 121, 211, 26, 73, 240, 76, 70, 133, 186, 165, 48, 31, 39, 3, 219, 96, 14, 166, 139, 24, 206, 93, 250, 79, 246, 256, 199, 198, 131, 34, 192, 173, 35, 0, 171, 160, 151, 118, 24, 10, 100, 93, 19, 101, 15, 190, 74, 10, 117, 4, 41, 135, 45, 107, 155, 152, 95, 222, 214, 174, 139, 117, 211, 224, 120, 219, 250, 1, 110, 225, 196, 105, 96, 52, 231, 59, 70, 95, 56, 58, 248, 171, 16, 251, 165, 54, 4, 211, 60, 210, 158, 45, 96, 105, 116, 30, 239, 96, 37, 175, 254, 157, 26, 151, 141, 43, 110, 227, 199, 223, 135, 162, 112, 4, 45, 66, 228, 162, 238, 165, 158, 27, 18, 76, 36, 237, 107, 84, 57, 233, 96, 72, 6, 114, 44, 119, 174, 59, 82, 202, 26, 216, 35, 55, 159, 113, 98, 4, 74, 2, 128, 34, 180, 191, 8, 101, 169, 157, 120, 254, 158, 97, 227, 79, 151, 167, 64, 195, 42, 250, 207, 213, 238, 199, 111, 149, 18, 194, 240, 53, 130, 3, 188, 41, 100, 255, 158, 21, 189, 19, 214, 127]
```


## Initial Analysis:

+ It strips the flag of the flag format, so no possibility of a known plaintext based attack

```py
xs = []
for i, c in enumerate(flag):
    xs += [ord(c)] * (i + 1)
```

+ Essentially, the above code gives the ascii value of the flag character, and it returns it `(i+1)` times where i is the index of the current flag character.
So essentially returns `abbcccdddd...`

```py
p = 257
print('output =', [sum(pow(x, k, p) for x in xs) % p for k in range(1, len(xs) + 1)])
```
+ What the above lines do is they raise each flag character to a power `k`, which ranges from 1 to 253 i.e., we get 253 polynomials of the form $$x_1 ^ k + 2x_2 ^ k + 3x_3 ^ k + ... + 22x_{22} ^ k$$ 
$$k \in [1,253]$$ 

All of this is under the modulus p, but let's forget about that for now.

## Solution Approach
+ Newton's identities are a prerequisite to solve this challenge (at least according to my solution approach)

<!-- $$
{\displaystyle p_{k}(x_{1},\ldots ,x_{n})=\sum _{i=1}^{n}x_{i}^{k}=x_{1}^{k}+\cdots +x_{n}^{k}}
$$ -->
$$
p_{k}(x_{1},...,x_{n}) = \sum_{i=1}^{n}x_{i}^{k} = x_{1} ^ {k} + ... + x_{n}^{k}
$$

+ Say
$$
\begin{aligned}
e_0(x_1, \ldots, x_n) &= 1, \\
e_1(x_1, \ldots, x_n) &= x_1 + x_2 + \cdots + x_n, \\
e_2(x_1, \ldots, x_n) &= \sum_{1 \leq i < j \leq n} x_i x_j, \\
&\vdots \\
e_n(x_1, \ldots, x_n) &= x_1 x_2 \cdots x_n, \\
e_k(x_1, \ldots, x_n) &= 0, \quad \text{for } k > n.
\end{aligned}
$$

Then,
$$
0 = \sum_{i=k-n}^{k} (-1)^{i-1} e_{k-i}(x_1, \ldots, x_n) p_i(x_1, \ldots, x_n)
$$

valid for all $n ≥ k ≥ 1$.

+ Essentially, this can be applied to the roots of a polynomial, 
$$
\prod_{i=1}^{n}(x-x_{i}) = \sum_{k=0}^{n}(-1)^{k}e_{k}x^{n-k}p_{k}(x_{1},\ldots ,x_{n}) = \sum_{i=1}^{n}x_{i}^{k}
$$

+ But our given output is of the format 
$$x_1 ^ k + 2x_2 ^ k + 3x_3 ^ k + ... + 22x_{22} ^ k$$ 
+ So ... how do we procede?
+ expand each of the coefficients. You get:

$$
x_1 ^ k + x_2 ^ k + x_2 ^ k +  x_3 ^ k + x_3^k + x_3^k + ... + x_{22} ^ k(22\space times)
$$

+ So, the roots of the resultant polynomial beocomes $[x_1,x_2(2\space times)... x_22 (22\space times)]$ where $[x_1,x_2...x_{22}]$ are the flag characters

+ The coefficients were meant to indicate the index of the flag character obtained based on the frequency of the root.

+ Now, we just apply the above identity to solve the challenge

## Solution

+ firstly we need to generate the list of e's (coefficients)

```py
E = []

for i in range(253):
    tmp = 0
    for j in range(i):
        tmp += ((-1)**j * E[j] * P[i-j-1]) % p
    tmp = (P[i] - tmp) % p
    ei = tmp * pow((-1)^i*(i+1),-1,p) % p
    E.append(ei)
```

+ next, we need to generate a's (just get the sign on e right)

```py
A = [1]

for i in range(len(E)):
    A.append(((-1)^(i+1) * E[i]) % p)
```

+ Now we just need to solve the polynomial generated and sort it according to frequency

```py
P.<x> = PolynomialRing(Zmod(p))

f = 0

for i in range(253):
    f += x^(253 - i) * A[i]
f += A[-1]

res = f.roots()

flag = [0 for i in range(22)]
for i in res:
    flag[i[1]-1] = chr(i[0])

print("TPCTF{" + "".join(flag) + "}")
```

+ The flag turns out to be `TPCTF{polyisfun_MJCQz:a^VX"G}`

The solve script can be found [here](solve.sage)