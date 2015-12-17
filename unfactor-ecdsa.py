import ecdsa
import binascii
import sys

primes = sys.argv[2:]

short_key_limit = 240  # if key cannot be found from factors, reduce this number

with open(sys.argv[1], "rb") as f:
    header = f.read(414)
    if not header.startswith('\xde\xad\xbe\xef\x04'):
        print sys.argv[1] + " doesn't appear to be TeslaCrypted"
        exit()
    for i in xrange(1<<len(primes)):
        x = 1
        for j in xrange(len(primes)):
            if i & 1<<j:
                x *= int(primes[j])
        if 1<<short_key_limit < x < 1<<256:
            pubkey = ecdsa.SigningKey.from_secret_exponent(x, curve=ecdsa.SECP256k1).verifying_key.to_string()
            if header[5:].startswith(pubkey):
                print "Found Bitcoin private key: %064X" % x
                exit()
            elif header[200:].startswith(pubkey):
                print "Found AES private key: %064X" % x
                exit()
