from Crypto.Util.number import long_to_bytes
import gmpy2

e = 4680013789992958764661
n = 113512878655961571626610562291692317083167898593072246908072509473338669866931624486434843922077792562235492835323939380660867587409311081240029070350808655984402585845023288249807250489084430773691893497493957878187939757801622886103893275017257035278212160216032814012251157961899906789943525036078018769313
U = 1931999207628789396725122770203483408911326042952326921451
V = 799504796180001663308018451701479236857150404193865300422493
c = 94105129348907954980205351665290609913865320383526984688577432708537003146181471259880907643772804194349299707552600926808992628679380768658711570812064692202538521952981150231103309549852666196113547591789678339722493939214907786911484309585843582998176263433226474196365066591224488571958002184788519619403
Q = 2**(512 - 313)  # Q = 2^199

e_val = e
D_val = e_val * U - 1
C_val = e_val * Q

k1_min = 1
k1_max = e_val - 1
found = False
p_val = None
q_val = None

for k1 in range(k1_min, k1_max + 1):
    if k1 % 10**6 == 0:
        print(f"Progress: k1 = {k1}")
    if gmpy2.gcd(2 * e_val, k1) != 1:
        continue
    g = gmpy2.gcd(C_val, k1)
    if g != 1:
        continue
    try:
        inv_Ck1 = gmpy2.invert(C_val, k1)
    except:
        continue
    a0 = (-D_val) % k1
    a0 = (a0 * inv_Ck1) % k1
    X0 = D_val + C_val * a0
    if X0 % k1 != 0:
        continue
    P0_val = X0 // k1
    p0_val = P0_val + 1
    p_candidate = p0_val
    q_test = n // p_candidate
    if p_candidate * q_test == n and q_test * p_candidate == n:
        p_val = p_candidate
        q_val = q_test
        found = True
        break
    if p0_val > 0 and n % p0_val == 0:
        p_val = p0_val
        q_val = n // p_val
        found = True
        break
    if found:
        break

if not found:
    for k1 in range(k1_min, k1_max + 1):
        if k1 % 10**6 == 0:
            print(f"Progress: k1 = {k1}")
        if gmpy2.gcd(2 * e_val, k1) != 1:
            continue
        try:
            inv_Ck1 = gmpy2.invert(C_val, k1)
        except:
            continue
        a0 = (-D_val) % k1
        a0 = (a0 * inv_Ck1) % k1
        X0 = D_val + C_val * a0
        if X0 % k1 != 0:
            continue
        P0_val = X0 // k1
        p0_val = P0_val + 1
        if p0_val == 1:
            continue
        t_low = (2**511 - p0_val) // C_val
        t_high = (2**512 - p0_val) // C_val + 1
        for t_val in range(t_low, t_high):
            p_candidate = p0_val + t_val * C_val
            if p_candidate > 2**512 or p_candidate <= p0_val:
                break
            if n % p_candidate == 0:
                p_val = p_candidate
                q_val = n // p_candidate
                found = True
                break
        if found:
            break
    if not found:
        print("Failed to find p and q with the first approach. Trying with the second approach using V.")
        for k1 in range(k1_min, k1_max + 1):
            if k1 % 10**6 == 0:
                print(f"Progress: k1 = {k1}")
            if gmpy2.gcd(2 * e_val, k1) != 1:
                continue
            try:
                inv_Ck1 = gmpy2.invert(C_val, k1)
            except:
                continue
            a0 = (-D_val) % k1
            a0 = (a0 * inv_Ck1) % k1
            X0 = D_val + C_val * a0
            if X0 % k1 != 0:
                continue
            P0_val = X0 // k1
            p0_val = P0_val + 1
            t_low = (2**511 - p0_val) // C_val
            t_high = (2**512 - p0_val) // C_val + 1
            for t_val in range(t_low, t_high):
                p_candidate = p0_val + t_val * C_val
                if p_candidate > 2**512:
                    break
                if n % p_candidate != 0:
                    continue
                q_candidate = n // p_candidate
                try:
                    v_candidate = gmpy2.invert(e_val, q_candidate - 1)
                except:
                    continue
                if v_candidate % Q == V:
                    p_val = p_candidate
                    q_val = q_candidate
                    found = True
                    break
            if found:
                break

if found:
    print("Found p and q")
    phi = (p_val - 1) * (q_val - 1)
    d = gmpy2.invert(e_val, phi)
    m = pow(c, int(d), n)
    flag = long_to_bytes(m)
    print(flag)
else:
    print("Failed to factor n")