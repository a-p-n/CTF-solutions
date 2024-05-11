import os
import hashlib

TRAVERSED = ['solve.py']


class Node(object):
    def __init__(self, dirname) -> None:
        self.dir = dirname

    def add_it(self, lst):
        for _ in lst:
            TRAVERSED.append(_)

    def calc_the_password(self, filename):
        if filename not in TRAVERSED:
            hashed_value = hashlib.md5(filename.encode()).hexdigest()
            return hashed_value

    def SevenUnZip(self, filename):
        if filename not in TRAVERSED and filename.split(".")[-1] == "7z":
            os.system(f"7z e {filename} -p{self.calc_the_password(filename)}")
            if filename.split(".")[-1] != "txt":
                os.system(f"rm {filename}")
            lst = [filename]
            self.add_it(lst)

    def get_the_pass(self):
        for packed in os.walk(self.dir):
            print(packed)
            temp = packed[2]
            temp.remove("solve.py")
            for _ in range(len(temp)):
                self.SevenUnZip(temp[_])

    def __call__(self):
        self.get_the_pass()


n = Node("/mnt/e/ctf/umdctf/ZR")
for _ in range(10):
    n()
print(TRAVERSED)
