P.<x> = PolynomialRing(GF(p))
points = [(i,outs[i]) for i in range(len(outs))]
f = P.lagrange_polynomial(points)
for i in range(101,133):
    flag += bytes([f(x=i)])

