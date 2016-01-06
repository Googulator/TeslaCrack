from __future__ import print_function
from Crypto.Cipher import AES
import binascii
import sys

def fix_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key

def main(file, primes, magic = b'%PDF'):
    known_file_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']
    ret = ""

    try:
        xrange
    except NameError:
        xrange = range

    prod = 1
    for i in xrange(len(primes)):
        prod *= int(primes[i])
    
    with open(file, "rb") as f:
        header = f.read(414)
        if header[:5] not in known_file_magics:
            return file + " doesn't appear to be TeslaCrypted"
        ecdh = int(header[0x108:0x188].rstrip(b'\0'), 16)
        cofactor = ecdh//prod
        if prod > ecdh:
            return "Superfluous factors or incorrect factorization detected!"
        if cofactor*prod != ecdh:
            return "Error: factors don't divide AES pubkey"
        if cofactor != 1:
            ret += "Warning: incomplete factorization, found cofactor %d\n" % cofactor
        
        data = f.read(16)
        found = False
        i = 1
        while i < 1<<len(primes):
            x = 1
            for j in xrange(len(primes)):
                if i & 1<<j:
                    x *= int(primes[j])
            if x < 1<<256 and ecdh//x < 1<<256 and AES.new(fix_key(binascii.unhexlify('%064x' % x)), AES.MODE_CBC, header[0x18a:0x19a]).decrypt(data).startswith(magic):
                ret += "Candidate AES private key: b'\\x" + '\\x'.join([('%064x' % x)[i:i+2] for i in xrange(0, 64, 2)]) + ("' (%064X)" % x) + "\n"
                found = True
            i += 1
        if cofactor != 1 and not found:
            i = 1
            while i < 1<<len(primes):
                x = cofactor
                for j in xrange(len(primes)):
                    if i & 1<<j:
                        x *= int(primes[j])
                if x < 1<<256 and ecdh//x < 1<<256 and AES.new(fix_key(binascii.unhexlify('%064x' % x)), AES.MODE_CBC, header[0x18a:0x19a]).decrypt(data).startswith(magic):
                    ret += "Candidate AES private key: b'\\x" + '\\x'.join([('%064x' % x)[i:i+2] for i in xrange(0, 64, 2)]) + ("' (%064X)" % x) + "\n"
                i += 1
    
    return ret
    
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: unfactor.py <sample file> <space-separated list of factors>")
        exit()
    print(main(sys.argv[1], sys.argv[2:]))
