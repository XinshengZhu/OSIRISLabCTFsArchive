from Crypto.Util import number
import os

bit_length = 2048

p = number.getPrime(bit_length, os.urandom)
q = number.getPrime(bit_length, os.urandom)

e = 3
n = p * q

with open("flag.txt", "r") as FILE:
    FLAG = FILE.read().strip()

m = int("".join(i.encode("hex") for i in FLAG), 16)

def encrypt(m, e, n):
    return hex(pow(m, e, n))

print(encrypt(m, e, n))
