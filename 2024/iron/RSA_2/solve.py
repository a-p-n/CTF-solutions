import Crypto.Util.number as cun


def roots_of_unity(e, phi, n, rounds=250):
    # Divide common factors of `phi` and `e` until they're coprime.
    phi_coprime = phi
    while gcd(phi_coprime, e) != 1:
        phi_coprime //= gcd(phi_coprime, e)

    # Don't know how many roots of unity there are, so just try and collect a bunch
    roots = set(pow(i, phi_coprime, n) for i in range(1, rounds))

    assert all(pow(root, e, n) == 1 for root in roots)
    return roots, phi_coprime

n, e, ct = 161643423646746552081298841935498903406728484661198088824380120820649408462211320026846900530120533720144166059852036274757176945943476154740893002954181911201068843959015760064479587114460816364946604976937998011320067074515344961776920419207973234413389567508538119203696918037349918054399980346807879167361, 36675, 59237480729804419902249350038380812764615310700084519548754724856780737977857097616843794684178008858466821286387353080178404910815575872547979820848851425285654302196414305127926468908308102733135120774714553727434912025225828846601760761868067655959956674559148988221195055343304319184971182998654695411365

# n is prime
# Problem: e and phi are not coprime - d does not exist
phi = n - 1

# Find e'th roots of unity modulo n
roots, phi_coprime = roots_of_unity(e, phi, n)

# Use our `phi_coprime` to get one possible plaintext
d = inverse_mod(e, phi_coprime)
pt = pow(ct, d, n)
assert pow(pt, e, n) == ct

# Use the roots of unity to get all other possible plaintexts
pts = [(pt * root) % n for root in roots]
pts = [cun.long_to_bytes(pt) for pt in pts]
print(pts)