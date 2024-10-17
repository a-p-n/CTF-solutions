import logging
from math import gcd

def roots_of_unity(ring, l, r):
    """
    Generates r-th roots of unity in a ring, with r | l.
    :param ring: the ring, with order n
    :param l: the Carmichael lambda of n
    :param r: r
    :return: a generator generating the roots of unity
    """
    assert l % r == 0, "r should divide l"

    x = ring(2)
    while (g := x ** (l // r)) == 1:
        x += 1

    for i in range(r):
        yield int(g ** i)

def rth_roots(Fq, delta, r):
    """
    Uses the Adleman-Manders-Miller algorithm to extract r-th roots in Fq, with r | q - 1.
    More information: Cao Z. et al., "Adleman-Manders-Miller Root Extraction Method Revisited" (Table 4)
    :param Fq: the field Fq
    :param delta: the r-th residue delta
    :param r: the r
    :return: a generator generating the rth roots
    """
    delta = Fq(delta)
    q = Fq.order()
    assert (q - 1) % r == 0, "r should divide q - 1"

    p = Fq(1)
    while p ** ((q - 1) // r) == 1:
        p = Fq.random_element()

    t = 0
    s = q - 1
    while s % r == 0:
        t += 1
        s //= r

    k = 1
    while (k * s + 1) % r != 0:
        k += 1
    alpha = (k * s + 1) // r

    a = p ** (pow(r, t - 1, q - 1) * s)
    b = delta ** (r * alpha - 1)
    c = p ** s
    h = 1
    for i in range(1, t):
        d = b ** pow(r, t - 1 - i, q - 1)
        logging.debug(f"Computing the discrete logarithm for {i = }, this may take a long time...")
        j = 0 if d == 1 else -d.log(a)
        b *= (c ** r) ** j
        h *= c ** j
        c **= r

    root = int(delta ** alpha * h)
    for primitive_root in roots_of_unity(Fq, q - 1, r):
        yield root * primitive_root % q


def attack(N, e, phi, c):
    """
    Computes possible plaintexts when e is not coprime with Euler's totient.
    More information: Shumow D., "Incorrectly Generated RSA Keys: How To Recover Lost Plaintexts"
    :param N: the modulus
    :param e: the public exponent
    :param phi: Euler's totient for the modulus
    :param c: the ciphertext
    :return: a generator generating possible plaintexts for c
    """
    assert phi % e == 0, "Public exponent must divide Euler's totient"
    if gcd(phi // e, e) == 1:
        assert is_prime(e), "Public exponent must be prime"
        phi //= e
        # Finding multiplicative generator of subgroup with order e elements (Algorithm 1).
        g = 1
        gE = 1
        while gE == 1:
            g += 1
            gE = pow(g, phi, N)

        # Finding possible plaintexts (Algorithm 2).
        d = pow(e, -1, phi)
        a = pow(c, d, N)
        l = gE
        for i in range(e):
            x = a * l % N
            l = l * gE % N
            yield x
    else:
        # Fall back to more generic root finding using Adleman-Manders-Miller and CRT.
        p, q = 125744600137007428336686588524997758583871561683692726713676285534301107098981040025358212893254808906490849809996401262081360657684811764499058585423566589418668455569756206340960309696630881351340690627578536523134632286484896258485029204377197049678809995370536434185505078509989342157694120501717398288147, 152338557313492806920938057132024177169537855797474186224778436724151018350841859306050747693427022538305746331468540077418496101170856031753174852597426413417774981047349677917782159366070625041741663841773378489741748290598624909537640900100213447631657455022547932304046202563857706877939270502191620357813
        tp = 0
        while (p - 1) % (e ** (tp + 1)) == 0:
            tp += 1
        tq = 0
        while (q - 1) % (e ** (tq + 1)) == 0:
            tq += 1

        assert tp > 0 or tq > 0
        cp = c % p
        cq = c % q
        logging.info(f"Computing {e}-th roots mod {p}...")
        mps = [pow(cp, pow(e, -1, p - 1), p)] if tp == 0 else list(rth_roots(GF(p), cp, e))
        logging.info(f"Computing {e}-th roots mod {q}...")
        mqs = [pow(cq, pow(e, -1, q - 1), q)] if tq == 0 else list(rth_roots(GF(q), cq, e))
        logging.info(f"Computing {len(mps) * len(mqs)} roots using CRT...")
        for mp in mps:
            for mq in mqs:
                yield int(crt([mp, mq], [p, q]))

N = 19155750974833741583193175954281590563726157170945198297004159460941099410928572559396586603869227741976115617781677050055003534675899765832064973073604801444516483333718433505641277789211533814981212445466591143787572063072012686620553662750418892611152219385262027111838502078590253300365603090810554529475615741997879081475539139083909537636187870144455396293865731172472266214152364966965486064463013169673277547545796210067912520397619279792527485993120983571116599728179232502586378026362114554073310185828511219212318935521752030577150436386831635283297669979721206705401841108223134880706200280776161816742511
e = 37929
p = 125744600137007428336686588524997758583871561683692726713676285534301107098981040025358212893254808906490849809996401262081360657684811764499058585423566589418668455569756206340960309696630881351340690627578536523134632286484896258485029204377197049678809995370536434185505078509989342157694120501717398288147
q = N//p
assert p * q == N
phi = (p - 1) * (q - 1)
c = 18360638515927091408323573987243771860358592808066239563037326262998090628041137663795836701638491309626921654806176147983008835235564144131508890188032718841579547621056841653365205374032922110171259908854680569139265494330638365871014755623899496058107812891247359641915061447326195936351276776429612672651699554362477232678286997748513921174452554559807152644265886002820939933142395032126999791934865013547916035484742277215894738953606577594559190553807625082545082802319669474061085974345302655680800297032801212853412563127910754108599054834023083534207306068106714093193341748990945064417347044638122445194693
for i in attack(N,e,phi,c):
    print(i)