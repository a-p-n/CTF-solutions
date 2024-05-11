---
title: Larisa - ASIS CTF Finals 2023
date: 2023-12-30 23:26:45
author: Hisoka
author_url: https://twitter.com/Hisokap3lol
categories:
  - Crypto
tags:
  - ASIS CTF 
  - RSA
  - Lattices
  - LLL
  - Coppersmith
mathjax: true
---

Detailed solution to the Larisa challenge from ASIS CTF Finals 2023

**tl;dr** 
+ Variable recovery using LLL
+ Factor recovery using Coppersmith


<!--more-->

**Challenge Points**: 122
**No. of Solves**: 35 
**Solved by**: [Hisoka]("https://twitter.com/Hisokap3lol") & [m0h1th]("")

## Challenge Description:
In our Larisa challenge first decrypt a mysterious cipher, unraveling hidden messages, and prove your cryptographic prowess in this ASIS CTF task.


## Intro:
This was a very good and interesting challenge from ASIS. It was classified as warmup, and was the only one we could solve in crypto. We had 3 minutes left in the CTF when we solved this challenge.

## Analysis
This challenge had two critical areas which could be exploited, both of which are in the key generation.

```py
def keygen(nbit):
        p = getPrime(nbit // 2)
        P, Q = [next_prime(p * getPrime(nbit // 2 - 10)) for _ in '01']
        n, K = P * Q, 2 ** (nbit >> 1)
        u, y = getRandomRange(1, n), getRandomRange(1, K)
        v = - (p + u * y) % n

        pkey = (u, v, n)
        skey = (y, P, Q)

        return pkey, skey
```

In the generation of the modulus, we generate the primes P and Q from a common prime p. 
$$P = p * a + d_1$$
$$Q = p * b + d_2$$

Where a, b are 502 bit primes.

This means that P and Q are not completely unrelated. 

The second vulnerability lies in generating v.

$$v = -(p + u \cdot y ) (mod \space n )$$

## Exploit:
There are two parts we need to clear to successfully solve this challenge.

+ Recover the prime p
+ Factorise n using p

Let's tackle the first part 

The only relation we have that might expose p is in the generation of v.
We cannot recover p (or y) using conventional algebra. We will be using lattices to solve for p and y.

### Initial Attempt:

$$v  = -(p + u \cdot y ) (mod \space n )$$  
$$v + p + u \cdot y = 0 (mod \space n ) $$
$$v + p + u \cdot y  - k \cdot n = 0$$

Now we need to construct a lattice such that the target vector contains p


$$
\begin{bmatrix}
1 & 0 & 0 & v \\
0 & 1 & 0 & 1 \\
0 & 0 & 1 & u \\
0 & 0 & 0 & -n\\
\end{bmatrix}
$$

The target vector of this lattice will be:

$$ 
\begin{bmatrix}
1 & p & y & 0
\end{bmatrix}
$$

We will need to take care of **minkowski's first theorem** to ensure that our target vector is the shortest vector

Turns out, our target vector doesn't satisify this condition. We can scale our lattice so that this condition is satisified. 

No matter how much we scale our lattice, LLL won't  give the desired target vector.

### Successful attempt:

$$v  = -(p + u \cdot y ) (mod \space n )$$ 
$$-v = p + u \cdot y \space (mod \space n)$$
$$p \times (-v)^{-1} + u \cdot (-v)^{-1} \cdot y = 1 \space (mod \space n) $$
$$p \times (-v)^{-1} + u \cdot (-v)^{-1} \cdot y - k \cdot n = 1$$

We can construct a Lattice using this relation

$$
\begin{bmatrix}
1 & 0 & (-v)^{-1} \\
0 & 1 & u \cdot (-v)^{-1} \\
0 & 0 & -n\\
\end{bmatrix}
$$

The target vector for this lattice is supposed to be 
$$ 
\begin{bmatrix}
p & y & 1 
\end{bmatrix}
$$

I don't exactly know what the issue was with the first lattice I constructed, but this seemed to spit out the desired p and y values 

The exploit:
```py
u = ...
v = ...
n = ...
c = ...

mvinv = inverse_mod(-v,n)

M = Matrix(QQ,[
  [1,0,mvinv],
  [0,1,u * mvinv],
  [0,0,-n]
])

p,y,_ = M.LLL()[0]

print(p,y)
```

Now, we have p (and y but y useless in recovering P and Q)

$$n = (p \cdot a + d_1) \cdot (p \cdot b + d_2)$$

Simplifying we get 

$$n = p^2 \cdot (a \cdot b) + p \cdot(a \cdot d_2 + b\cdot d_1) + d1d2$$

$$d1 \cdot d2 \leq p$$

so $n \equiv d1d2 (mod \space p)$

```py
dd = n % p 
```

Now, we run through every divisor of d1d2 to bruteforce d1 and d2 and find the roots of the equaton $n = (p \cdot a + d_1) \cdot (p \cdot b + d_2)$

This is a bivariate equation, which we need to solve for a and b.
We can attempt to use Coppersmith's method to solve this.

For this, we use [defund's coppersmith]("https://github.com/defund/coppersmith")

The bounds for small roots will be from 500 to 514 bits

```py
load("coppersmith/coppersmith.sage")

for d in divisors(dd):
    
    bounds = (2**500,2**514)
    R = Integers(n)
    P.<x, y> = PolynomialRing(R)
    
    f = n - (p * x + d) * (p * y + dd//d)
    temp = small_roots(f, bounds)
    if len(temp) > 0:
        a,b = temp[0]
        if n % (p * a + d) == 0:
            print("found P")
            P = int(p * a + d)
            print(P)
            print(a)
            print(d)
            break
```

For this, we get 

```
P = 71218615726986279579370668139037142689966647052101441376430015830838231199171548196922446463175467171561268563623769256785550754271365459397434046094388001196147252051477547109852902721227906240788622672382502774317531886362352572991236275451876609744879399488927656725096880234800278345494059161505335663

a = 9982434694399603508133337302525981381172077094594547911881389765404140839294990193381283506463508822263498107585942085834150918110565475926894148950133

d = 360
```

From here, it's just typical RSA decryption to get the flag

```py
Q = n//P

print(bytes.fromhex(hex((pow(c,pow(e,-1,(P - 1) * (Q - 1)),n) + v) * pow(u,-1,n))[2:]).decode())
```

`FLAG : ASIS{__fpLLL__4pPL1cA7!0n5_iN_RSA!!!}`

