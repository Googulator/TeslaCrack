from __future__ import print_function

import binascii
import logging
import sys

from Crypto.Cipher import AES


log = logging.getLogger('undecrypt')


def fix_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key

def undecrypt(file, primes, magic = b'%PDF'):
    known_file_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

    ret = ""

    try:
        xrange  # @UndefinedVariable
    except NameError:
        xrange = range

    primes = [int(p) for p in primes]
    log.info('Primes: \n  %s' % '\n  '.join(str(p) for p in primes))
    prod = 1
    for p in primes:
        if p >= 1<<256:
            return "Factor too large: %s" % p
        prod *= p

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


def main(*args):
    """Parse args, setup logging and delegate to :func:`teslacrack()`."""
    if not args:
        args = sys.argv

    log_level = logging.INFO
    frmt = "%(asctime)-15s:%(levelname)3.3s: %(message)s"
    logging.basicConfig(level=log_level, format=frmt)
    log.debug('Args: %s', args)

    file = sys.argv[1]
    primes = sys.argv[2:]
    return undecrypt(file, primes)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: unfactor.py <sample file> <space-separated list of factors>")
        exit()
    print(main())
