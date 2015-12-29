# TeslaCrypt cracker
#
# by Googulator
# 
# To use, factor the 2nd hex string found in the headers of affected files using msieve.
# The AES-256 key will be one of the factors, typically not a prime - experiment to see which one works.
# Insert the hex string & AES key below, under known_keys, then run on affected directory.
# If an unknown key is reported, crack that one using msieve, then add to known_keys and re-run.
#
# This script requires pycrypto to be installed.
#
# Enjoy! ;)

import sys
import os
import posixpath
from Crypto.Cipher import AES
import struct

known_keys = {
    'D4E0010A8EDA7AAAE8462FFE9562B29871B9DA186D98B5B15EC9F77803B60EAB12ADDF78CBD4D9314A0C31270CC8822DCC071D10193D1E612360B26582DAF124': b'\xEA\x68\x5A\x3C\xDB\x78\x0D\xF2\x12\xEB\xAA\x50\x03\xAD\xC3\xE1\x04\x06\x3E\xBC\x25\x93\x52\xC5\x09\x88\xB7\x56\x1A\xD1\x34\xA5',
    '9F2874FB536C0A6EF7B296416A262A8A722A38C82EBD637DB3B11232AE0102153C18837EFB4558E9E2DBFC1BB4BE799AE624ED717A234AFC5E2F8E2668C76B6C': b'\xCD\x0D\x0D\x54\xC4\xFD\xB7\x64\x7C\x4D\xB0\x95\x6A\x30\x46\xC3\x4E\x38\x5B\x51\xD7\x35\xD1\x7C\x00\x9D\x47\x3E\x02\x84\x27\x95',
    '115DF08B0956AEDF0293EBA00CCD6793344D6590D234FE0DF2E679B7159E8DB05F960455F17CDDCE094420182484E73D4041C39531B5B8E753E562910561DE52': b'\x1A\xDC\x91\x33\x3E\x8F\x6B\x59\xBB\xCF\xB3\x34\x51\xD8\xA3\xA9\x4D\x14\xB3\x84\x15\xFA\x33\xC0\xF7\xFB\x69\x59\x20\xD3\x61\x8F',
}

extension = '.vvv'
known_file_magics = ['\xde\xad\xbe\xef', '\x00\x00\x00\x00']

delete = False

unknown_keys = {}

unknown_btkeys = {}

def fix_key(key):
    while key[0] == '\0':
        key = key[1:] + '\0'
    return key

def decrypt_file(path):
    try:
        do_unlink = False
        with open(path, "rb") as fin:
            header = fin.read(414)
            
            if header[:4] not in known_file_magics:
                print path + " doesn't appear to be TeslaCrypted"
                return
            
            if header[0x108:0x188] not in known_keys:
                if header[0x108:0x188] not in unknown_keys:
                    unknown_keys[header[0x108:0x188]] = path
                if header[0x45:0xc5] not in unknown_btkeys:
                    unknown_btkeys[header[0x45:0xc5]] = path
                print "Cannot decrypt {}, unknown key".format(path)
                return
            
            decryptor = AES.new(fix_key(known_keys[header[0x108:0x188].rstrip('\0')]), AES.MODE_CBC, header[0x18a:0x19a])
            size = struct.unpack('<I', header[0x19a:0x19e])[0]
            
            if not os.path.exists(os.path.splitext(path)[0]):
                print "Decrypting {}".format(path)
                fout = open(os.path.splitext(path)[0], 'wb')
                data = fin.read()
                fout.write(decryptor.decrypt(data)[:size])
                if delete:
                    do_unlink = True
            else:
                print "Not decrypting {}, decrypted copy already exists".format(path)
        if do_unlink:
            os.unlink(path)
    except Exception:
        raise
        print "Error decrypting {}, please try again".format(path)
        
def traverse_directory(path):
    try:
        for entry in os.listdir(path):
            if os.path.isdir(posixpath.join(path, entry)):
                traverse_directory(posixpath.join(path, entry))
            # TODO add other known extensions
            elif entry.endswith(extension) and os.path.isfile(posixpath.join(path, entry)):
                decrypt_file(posixpath.join(path, entry))
    except Exception as e:
        print "Cannot access " + path
    
def main(args):
    path = '.'
    global delete
    
    for arg in args:
        if arg == "--delete":
            delete = True
        else:
            path = arg

    traverse_directory(path)
    if unknown_keys:
        print "Software has encountered the following unknown AES keys, please crack them first using msieve:"
        for key in unknown_keys:
            print key + " found in " + unknown_keys[key]
        print "Alternatively, you can crack the following Bitcoin key(s) using msieve, and use them with TeslaDecoder:"
        for key in unknown_btkeys:
            print key + " found in " + unknown_btkeys[key]
    
if __name__=='__main__':
    main(sys.argv[1:])
