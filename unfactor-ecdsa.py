import ecdsa
import binascii
import sys

def main(args, short_key_limit = 240):
    if len(args) < 2:
        print "usage: unfactor-ecdsa.py <sample file> <space-separated list of factors>"

    primes = args[1:]

    pubkeys = {}
    
    known_file_magics = ['\xde\xad\xbe\xef', '\x00\x00\x00\x00']

    with open(args[0], "rb") as f:
        header = f.read(414)
        if header[:4] not in known_file_magics:
            print argv[0] + " doesn't appear to be TeslaCrypted"
            return
        for i in xrange(1<<len(primes)):
            x = 1
            for j in xrange(len(primes)):
                if i & 1<<j:
                    x *= int(primes[j])
            if 1<<short_key_limit < x < 1<<256:
                if x not in pubkeys:
                    pubkeys[x] = ecdsa.SigningKey.from_secret_exponent(x, curve=ecdsa.SECP256k1).verifying_key.to_string()
                if header[5:].startswith(pubkeys[x]):
                    print "Found Bitcoin private key: %064X" % x
                    return
                elif header[200:].startswith(pubkeys[x]):
                    print "Found AES private key: b'\\x" + '\\x'.join([('%064x' % x)[i:i+2] for i in xrange(0, 64, 2)]) + "' (%064X)" % x
                    return

    print "No keys found, check your factors!"
    
if __name__ == "__main__":
    main(sys.argv[1:])
