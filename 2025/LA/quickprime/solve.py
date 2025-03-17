from Crypto.Util.number import isPrime, long_to_bytes
import gmpy2

def trial_division(n, limit=10**6):
    """Try small prime factors first."""
    for i in range(2, limit):
        if n % i == 0:
            return i, n // i
    return None, None

def fermat_factor(n):
    """Fermat's factorization method (works well when factors are close together)."""
    x = gmpy2.isqrt(n) + 1
    while True:
        y2 = x * x - n
        y = gmpy2.isqrt(y2)
        if y * y == y2:
            return int(x - y), int(x + y)
        x += 1

def factor_n(n, a, c, m):
    # Attempt trial division first
    p, q = trial_division(n)
    if p and q:
        return p, q
    
    # If trial division fails, try Fermat's method
    p, q = fermat_factor(n)
    if p and q and isPrime(p) and isPrime(q):
        if (a * p + c) % m == q % m:
            return p, q
        if (a * q + c) % m == p % m:
            return q, p
    return None, None

a = 2436850468785702489540582769232761695749785792960651105491236488397220313263504566059290809382933861099696879083107144400910220829935811952738192254346805
c = 10558332504375328981991260999536505641472139055424578997035199338079311804457221251326820131100002583417803282647853808580017392024963965335261357404396947
m = 1 << 512
n = 1166669195904963615356481657325590961436714444389553123456788616479729866543974207352334617284796103369676617492299041577389375612477527579721126141700651556521204950536452177616773710367475652800447857910829829653614917059626478510782400258618028096593141458171701566275372393096049695858779040132558629431

e = 65537
ct = 190016691452627214749189920567984923946723922852680299314693711791586164822999717652823589139688584539509147919044785350669783431555534710648932458843821927029851179573366959807662165467230826137461051404633711775498974929854254802441827205644994503643955139294536288739028444659547399492259931085466448759

p, q = factor_n(n, a, c, m)

if p and q:
    print(f"Found factors: p={p}, q={q}")
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    message = pow(ct, d, n)
    print("Decrypted flag:", long_to_bytes(message).decode())
else:
    print("Failed to factor n with LCG constraints.")
