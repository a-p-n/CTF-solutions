from z3 import *
from IPython import embed

p = 321640808977840043929611978280267560353
embed()
print("Test")
solver = Solver()

nbit = 128
u = BitVec('u', nbit)
v = BitVec('v', nbit)
w = BitVec('w', nbit)
x = BitVec('x', nbit)
y = BitVec('y', nbit)
z = BitVec('z', nbit)
k = p - 1

solver.add(Distinct(u, v, w, x, y, z))

solver.add(u % p != 0)
solver.add(v % p != 0)
solver.add(w % p != 0)
solver.add(x % p != 0)
solver.add(y % p != 0)
solver.add(z % p != 0)

eqn = (
    (1 + v * w * x * y * z) % p +
    (1 + u * w * x * y * z) % p +
    (1 + v * u * x * y * z) % p +
    (1 + v * w * u * y * z) % p +
    (1 + v * w * x * u * z) % p +
    (1 + v * w * x * y * u) % p
)

solver.add(eqn == 0)

if solver.check() == sat:
    model = solver.model()
    u_val = model[u].as_long()
    v_val = model[v].as_long()
    w_val = model[w].as_long()
    x_val = model[x].as_long()
    y_val = model[y].as_long()
    z_val = model[z].as_long()
    
    print(f"u = {u_val}")
    print(f"v = {v_val}")
    print(f"w = {w_val}")
    print(f"x = {x_val}")
    print(f"y = {y_val}")
    print(f"z = {z_val}")
else:
    print("No solution found.")