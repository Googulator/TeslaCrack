from __future__ import print_function
import ecdsa
import binascii
import sys

def main(file, primes, short_key_limit = 240):
    pubkeys = {}
    known_file_magics = ['\xde\xad\xbe\xef\x04', '\x00\x00\x00\x00\x04']

    with open(file, "rb") as f:
        header = f.read(414)
        if header[:5] not in known_file_magics:
            return file + " doesn't appear to be TeslaCrypted"
        for i in xrange(1<<len(primes)):
            x = 1
            for j in xrange(len(primes)):
                if i & 1<<j:
                    x *= int(primes[j])
            if 1<<short_key_limit < x < 1<<256:
                if x not in pubkeys:
                    pubkeys[x] = ecdsa.SigningKey.from_secret_exponent(x, curve=ecdsa.SECP256k1).verifying_key.to_string()
                if header[5:].startswith(pubkeys[x]):
                    return "Found Bitcoin private key: %064X" % x
                elif header[200:].startswith(pubkeys[x]):
                    return "Found AES private key: b'\\x" + '\\x'.join([('%064x' % x)[i:i+2] for i in xrange(0, 64, 2)]) + "' (%064X)" % x

    return "No keys found, check your factors!"
    
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: unfactor_ecdsa.py <sample file> <space-separated list of factors>")
    print(main(sys.argv[1], sys.argv[2:]))
