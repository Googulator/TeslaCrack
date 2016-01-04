from __future__ import print_function
from Crypto.Cipher import AES
import binascii
import sys

def fix_key(key):
    while key[0] == '\0':
        key = key[1:] + '\0'
    return key

def main(file, primes, magic = '%PDF', short_key_limit = 240):
    known_file_magics = ['\xde\xad\xbe\xef\x04', '\x00\x00\x00\x00\x04']
    ret = ""
    
    with open(file, "rb") as f:
        header = f.read(414)
        if header[:5] not in known_file_magics:
            return file + " doesn't appear to be TeslaCrypted"
        data = f.read(16)
        for i in xrange(1<<len(primes)):
            x = 1
            for j in xrange(len(primes)):
                if i & 1<<j:
                    x *= int(primes[j])
            if 1<<short_key_limit < x < 1<<256 and AES.new(fix_key(binascii.unhexlify('%064x' % x)), AES.MODE_CBC, header[0x18a:0x19a]).decrypt(data).startswith(magic):
                ret += "Candidate AES private key: b'\\x" + '\\x'.join([('%064x' % x)[i:i+2] for i in xrange(0, 64, 2)]) + ("' (%064X)" % x) + "\n"
    
    return ret
    
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: unfactor.py <sample file> <space-separated list of factors>")
    print(main(sys.argv[1], sys.argv[2:]))
