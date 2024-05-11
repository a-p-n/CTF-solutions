from Crypto.Util.number import long_to_bytes
from multiprocessing import Process
import time

THREADS = 16

threads = []


def convert(msg, x):
    msg ^= msg >> x
    msg ^= msg << 13 & 275128763
    msg ^= msg << 20 & 2186268085
    msg ^= msg >> 14
    return msg


def transform(num, x):
    return long_to_bytes(convert(num, x), 4)


def brute_force(start, end, target):
    x = 9
    for i in range(start, end):
        if transform(i, x) in target:
            print("Found: %s, Bytes: %s" % ((i, x), long_to_bytes(i)))
    return


def main():
    c = bytes.fromhex(
        'e34a707c5c1970cc6375181577612a4ed07a2c3e3f441d6af808a8acd4310b89bd7e2bb9')
    c = [c[i*4:i*4+4] for i in range(len(c))]

    start_num = 2**24
    end_num = 2**32

    chunk_size = (end_num - start_num) // THREADS

    for i in range(start_num, end_num, chunk_size):
        threads.append(Process(target=brute_force, args=(i, i+chunk_size, c)))
        threads[-1].start()

    time.sleep(10800)


if __name__ == "__main__":
    main()
