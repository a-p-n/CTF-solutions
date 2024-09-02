from functools import namedtuple

Point = namedtuple("Point", ["x", "y"])
R = RealField(prec=800)
inf = Point(R(0), R(1))

def lift_x(x):
    return Point(x, sqrt(x**3 - R(3) * x - R(2)))

def add(P, Q):
    if P.x == Q.x and P.y != Q.y:
        return inf
    elif P.y == Q.y:
        raise ValueError("Points have to differ!")
    elif P == inf:
        return Q
    elif Q == inf:
        return P

    lambda_ = (P.y - Q.y) / (P.x - Q.x)

    xr = lambda_**2 - P.x - Q.x
    yr = lambda_ * (Q.x - xr) - Q.y
    return Point(xr, yr)

def double(P):
    if P == inf:
        return P

    lambda_ = (R(3) * P.x**2 - R(3)) / (R(2) * P.y)

    xr = lambda_**2 - 2 * P.x
    yr = lambda_ * (P.x - xr) - P.y
    return Point(xr, yr)

def multiply_by_scalar(P, n: int):
    if n == 0 or P == inf:
        return inf
    elif n < 0:
        return multiply_by_scalar(Point(-P.x, P.y), -n)

    R0, R1 = P, double(P)
    for b in bin(n)[3:]:
        if b == "0":
            R0, R1 = double(R0), add(R0, R1)
        else:
            R0, R1 = add(R0, R1), double(R1)
    return R0

with open("./shes-the-real-one/output.dump", 'rb') as f:
    P, Q = loads(f.read())

def brute_force_discrete_log(P, Q, max_s):
    for s in range(max_s):
        if multiply_by_scalar(P, s) == Q:
            return s
    return None

max_s = 2**33
s = brute_force_discrete_log(P, Q, max_s)
if s is not None:
    print(f"Recovered scalar s: {s}")
else:
    print("Failed to recover scalar s")