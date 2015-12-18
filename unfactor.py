from Crypto.Cipher import AES
import binascii
import sys

def main(args, magic = '%PDF', short_key_limit = 240):
    if len(args) <= 2:
        print "usage: unfactor-ecdsa.py <sample file> <space-separated list of factors>"

    primes = args[1:]

    with open(args[0], "rb") as f:
        header = f.read(414)
        if not header.startswith('\xde\xad\xbe\xef\x04'):
            print args[0] + " doesn't appear to be TeslaCrypted"
            return
        data = f.read(16)
        for i in xrange(1<<len(primes)):
            x = 1
            for j in xrange(len(primes)):
                if i & 1<<j:
                    x *= int(primes[j])
            if 1<<short_key_limit < x < 1<<256 and AES.new(binascii.unhexlify('%064x' % x), AES.MODE_CBC, header[0x18a:0x19a]).decrypt(data).startswith(magic):
                print "Candidate AES private key: b'\\x" + '\\x'.join([('%064x' % x)[i:i+2] for i in xrange(0, 64, 2)]) + "' (%064X)" % x
            
if __name__ == '__main__':
    main(sys.argv[1:])