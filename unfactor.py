from Crypto.Cipher import AES
import binascii

primes = [  # these are example values, replace them with the primes you get from msieve!
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
]

magic = '%PDF'  # for a pdf file - change to the correct file magic if your sample.vvv is not a pdf

iv = b'\x27\x51\x0A\xBF\x31\x8D\x69\x26\x17\x78\x97\x2B\x98\x7D\xF6\x9F'

with open("sample.vvv", "rb") as f:
        header = f.read(414)
    data = f.read(16)
    for i in xrange(1<<len(primes)):
        x = 1
        for j in xrange(len(primes)):
            if i & 1<<j:
                x *= primes[j]
        if 1<<224 < x < 1<<256 and AES.new(binascii.unhexlify('%064x' % x), AES.MODE_CBC, iv).decrypt(data).startswith(magic):
            print hex(x).upper() + " " + AES.new(binascii.unhexlify('%064x' % x), AES.MODE_CBC, iv).decrypt(data)
