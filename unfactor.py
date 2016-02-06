from __future__ import print_function

import binascii
import logging
import sys

from Crypto.Cipher import AES

known_file_magics = {
    'pdf': b'%PDF',
    'doc': b'\xd0\xcf\x11\xe0',
    'zip': 'PK', 'xlsx': b'PK', 'xlsmx': b'PK', 'docx': b'PK', 'odf': b'PK',
    'jpg': b'\xFF\xD8\xFF',
    'png': b'\x89PNG\r\n\x1A\n',
    'mp3': b'\x42\x4D',
    'gif': b'GIF89a', 'gif': b'GIF87a',
    'bz2': b'BZh', 'tbz2': b'BZh',
    'gz': b'\x1F\x8B', 'tgz': b'\x1F\x8B',
    '7z': b'7z\xBC\xAF\x27\x1C',
    'rar': b'Rar!\x1A\x07\x00',
}
tesla_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

log = logging.getLogger('unfactor')



def fix_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key


def fix_hex_key(int_key):
    return fix_key(binascii.unhexlify('%064x' % int_key))


def is_known_file(fname, fbytes):
    for ext, magic_bytes in known_file_magics.items():
        if '.%s.' % ext in fname.lower() and fbytes.startswith(magic_bytes):
            return True


def undecrypt(fpath, primes):
    ret = ""

    try:
        xrange  # @UndefinedVariable
    except NameError:
        xrange = range

    prod = 1
    for p in primes:
        if p >= 1<<256:
            return "Factor too large: %s" % p
        prod *= p

    with open(fpath, "rb") as f:
        header = f.read(414)
        if header[:5] not in tesla_magics:
            return fpath + " doesn't appear to be TeslaCrypted"
        ecdh = int(header[0x108:0x188].rstrip(b'\0'), 16)
        cofactor = ecdh//prod
        if prod > ecdh:
            return "Superfluous factors or incorrect factorization detected!"
        if cofactor*prod != ecdh:
            return "Error: factors don't divide AES pubkey"
        if cofactor != 1:
            ret += "Warning: incomplete factorization, found cofactor %d\n" % cofactor

        data = f.read(16)
        init_vector = header[0x18a:0x19a]
        def decrypt_AES_file(aes_key, data):
            return AES.new(aes_key, AES.MODE_CBC, init_vector).decrypt(data)


        found = False
        i = 1
        while i < 1<<len(primes):
            x = 1
            for j in xrange(len(primes)):
                if i & 1<<j:
                    x *= int(primes[j])
            if (x < 1<<256 and ecdh//x < 1<<256 and is_known_file(
                    fpath, decrypt_AES_file(fix_hex_key(x), data))):
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
                if x < 1<<256 and ecdh//x < 1<<256 and is_known_file(
                        fpath, decrypt_AES_file(fix_hex_key(x), data)):
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
    primes = [int(p) for p in sys.argv[2:]]
    log.info('Primes: \n  %s' % '\n  '.join(str(p) for p in primes))

    return undecrypt(file, primes)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: unfactor.py <sample file> <space-separated list of factors>")
        exit()
    print(main())
