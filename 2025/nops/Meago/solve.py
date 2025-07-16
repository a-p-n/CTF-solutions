from sage.all import RealField
from Crypto.Util.number import long_to_bytes
from pwn import remote

nbit = 100
prec = 4 * nbit
R = RealField(prec)

def ys_until_converged(r, y0_R, max_iter=200, threshold=1e-90):
    for _ in range(5):
        r.recvuntil(b"[Q]uit\n")
        r.sendline(b"m")
        r.recvline()

    y_prev = y0_R
    for i in range(max_iter):
        r.recvuntil(b"[Q]uit\n")
        r.sendline(b"m")
        raw = r.recvline().strip().decode()
        _, _, y_str = raw.partition("y = ")
        y_cur = R(y_str)

        if abs(y_cur - y_prev) < R(threshold):
            print(f"[+] Converged after {i+1} iterations")
            return y_cur
        y_prev = y_cur
    print(f"[-] Did not converge within {max_iter} iterations, using last y")
    return y_cur

def recover_flag(host, port):
    r = remote(host, port)

    r.recvuntil(b"We know y0 = ")
    y0_line = r.recvline().strip().decode()
    y0_R = R(y0_line)

    y_inf = ys_until_converged(r, y0_R, max_iter=200, threshold=1e-155)

    x0 = (y_inf ** (R(7)/3)) / (y0_R ** (R(4)/3))

    for l in range(1, 200):
        candidate = (x0 * 10**l).round()
        if abs(R(candidate)/10**l - x0) < R(1e-155):
            m_int = int(candidate)
            try:
                fb = long_to_bytes(m_int)
                fs = fb.decode("ascii", errors="ignore")
                if "N0PS{" in fs.upper():
                    print(f"[+] Found flag with l = {l}: {fs}")
            except Exception:
                continue
    print("[-] No printable flag found.")
    return None

HOST = "0.cloud.chals.io"
PORT = 22748
flag = recover_flag(HOST, PORT)
if flag:
    print("\nFLAG = ", flag)
else:
    print("\nNo flag.")