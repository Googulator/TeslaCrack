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
#EXAMPLES:
#
# python teslacrack -v                          ## Decrypts current-folder, logging verbosely.
# python teslacrack .  bar\cob.xlsx             ## Decrypts current-folder & file(s).
# python teslacrack foo.pdf.cc  bar\cob.xlsx  C:\
# python teslacrack C:\\ --overwrite            ## Overwirte already decrypted files.
# python teslacrack C:\\ --overwrite --delete   ## Delete encrypted-files after decrypting them.
# python teslacrack C:\\ --delete-old           ## WILL DELETE ALL `.vvv` files!!!
#
# Enjoy! ;)

import logging
import os
from os.path import join as pjoin
import struct
import sys
import time

from Crypto.Cipher import AES


log = logging.getLogger('teslacrack')

# Add your (AES-key: priv-key) pairs here, like the examples below.
known_keys = {
    b'D4E0010A8EDA7AAAE8462FFE9562B29871B9DA186D98B5B15EC9F77803B60EAB12ADDF78CBD4D9314A0C31270CC8822DCC071D10193D1E612360B26582DAF124': b'\xEA\x68\x5A\x3C\xDB\x78\x0D\xF2\x12\xEB\xAA\x50\x03\xAD\xC3\xE1\x04\x06\x3E\xBC\x25\x93\x52\xC5\x09\x88\xB7\x56\x1A\xD1\x34\xA5',
    b'9F2874FB536C0A6EF7B296416A262A8A722A38C82EBD637DB3B11232AE0102153C18837EFB4558E9E2DBFC1BB4BE799AE624ED717A234AFC5E2F8E2668C76B6C': b'\xCD\x0D\x0D\x54\xC4\xFD\xB7\x64\x7C\x4D\xB0\x95\x6A\x30\x46\xC3\x4E\x38\x5B\x51\xD7\x35\xD1\x7C\x00\x9D\x47\x3E\x02\x84\x27\x95',
    b'115DF08B0956AEDF0293EBA00CCD6793344D6590D234FE0DF2E679B7159E8DB05F960455F17CDDCE094420182484E73D4041C39531B5B8E753E562910561DE52': b'\x1A\xDC\x91\x33\x3E\x8F\x6B\x59\xBB\xCF\xB3\x34\x51\xD8\xA3\xA9\x4D\x14\xB3\x84\x15\xFA\x33\xC0\xF7\xFB\x69\x59\x20\xD3\x61\x8F',
    b'7097DDB2E5DD08950D18C263A41FF5700E7F2A01874B20F402680752268E43F4C5B7B26AF2642AE37BD64AB65B6426711A9DC44EA47FC220814E88009C90EA': b'\x01\x7b\x16\x47\xd4\x24\x2b\xc6\x7c\xe8\xa6\xaa\xec\x4d\x8b\x49\x3f\x35\x51\x9b\xd8\x27\x75\x62\x3d\x86\x18\x21\x67\x14\x8d\xd9',
}

tesla_extensions = ['.vvv', '.ccc']  # Add more known extensions.

known_file_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

## CMD-OPTIONS
##
delete = False      # Delete encrypted-files after decrypting them.
delete_old = False  # Like `delete`, even if not decrypting it (existed from previous runs).
overwrite = False   # Overwirte already decrypted files.
verbose = False     # Verbosely log(DEBUG) all files visited.

unknown_keys = {}
unknown_btkeys = {}

## STATS
#
visit_nfiles = bad_nfiles = encrypt_nfiles = decrypt_nfiles = overwrite_nfiles = 0
deleted_nfiles = skip_nfiles = unknown_nfiles = failed_nfiles = 0

PROGRESS_INTERVAL_SEC = 10 # Log stats every that many files processed.
last_progress_time = time.time()

def fix_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key


def decrypt_file(path):
    global encrypt_nfiles, decrypt_nfiles, skip_nfiles, deleted_nfiles, \
            failed_nfiles, unknown_nfiles, overwrite_nfiles

    encrypt_nfiles += 1
    try:
        do_unlink = False
        with open(path, "rb") as fin:
            header = fin.read(414)

            if header[:5] not in known_file_magics:
                log.info("File %r doesn't appear to be TeslaCrypted.", path)
                skip_nfiles += 1
                return

            aes_encrypted_key = header[0x108:0x188].rstrip(b'\0')
            if aes_encrypted_key not in known_keys:
                if aes_encrypted_key not in unknown_keys:
                    unknown_keys[aes_encrypted_key] = path
                btc_key = header[0x45:0xc5].rstrip(b'\0')
                if btc_key not in unknown_btkeys:
                    unknown_btkeys[btc_key] = path
                log.error("Unknown key in file: %s", path)
                unknown_nfiles += 1
                return


            decrypt_existed = os.path.exists(os.path.splitext(path)[0])
            if overwrite or not decrypt_existed:
                log.debug("Decrypting%s: %s",
                        '(overwrite)' if decrypt_existed else '', path,)
                decryptor = AES.new(
                        fix_key(known_keys[aes_encrypted_key]),
                        AES.MODE_CBC, header[0x18a:0x19a])
                size = struct.unpack('<I', header[0x19a:0x19e])[0]
                fout = open(os.path.splitext(path)[0], 'wb')
                data = fin.read()
                fout.write(decryptor.decrypt(data)[:size])
                if delete and not decrypt_existed or delete_old:
                    do_unlink = True
                decrypt_nfiles += 1
                overwrite_nfiles += decrypt_existed
            else:
                log.debug("Skip decrypting %r, decrypted-copy already exists.", path)
                skip_nfiles += 1
                if delete_old:
                    do_unlink = True
        if do_unlink:
            os.unlink(path)
            deleted_nfiles += 1
    except Exception as e:
        failed_nfiles += 1
        log.error("Error decrypting %r due to %r!  Please try again.",
                path, e, exc_info=verbose)


def traverse_directory(fpath):
    global visit_nfiles, bad_nfiles, last_progress_time

    if time.time() - last_progress_time > PROGRESS_INTERVAL_SEC:
        last_progress_time = time.time()
        log_stats()
        log_unknown_keys()

    try:
        if os.path.isfile(fpath):
            visit_nfiles += 1
            if os.path.splitext(fpath)[1] in tesla_extensions:
                decrypt_file(fpath)
        else:
            for child in os.listdir(fpath):
                traverse_directory(pjoin(fpath, child))
    except Exception as e:
        bad_nfiles += 1
        log.error("Cannot access %r due to: %r", fpath, e, exc_info=verbose)


def log_unknown_keys():
    if unknown_keys:
        #assert len(unknown_keys) == len(unknown_btkeys, ( unknown_keys, unknown_btkeys)
        aes_keys = dict((fpath, key) for key, fpath in unknown_keys.items())
        btc_keys = dict((fpath, key) for key, fpath in unknown_btkeys.items())
        key_msgs = ["     AES: %r\n     BTC: %r\n    File: %r" %
                (aes_key.decode(), btc_keys.get(fpath, b'').decode(), fpath)
                for fpath, aes_key in aes_keys.items()]
        log.info("+++Unknown key(s) encountered: %i \n%s\n"
                "  Use `msieve` on AES-key(s), or `msieve` + `TeslaDecoder` on Bitcoin-key(s) to crack them!",
                len(unknown_keys), '\n'.join(key_msgs))


def log_stats():
    log.info("+++Files processed: "
            "\n    visited: %7i"
            "\n        bad:%5i"
            "\n  encrypted:%5i"
            "\n    decrypted:%5i"
            "\n    overwritten:%5i"
            "\n      deleted:%5i"
            "\n      skipped:%5i"
            "\n      unknown:%5i"
            "\n       failed:%5i",
        visit_nfiles, bad_nfiles, encrypt_nfiles, decrypt_nfiles,
        overwrite_nfiles, deleted_nfiles, skip_nfiles, unknown_nfiles,
        failed_nfiles)


def main(args):
    global verbose, delete, delete_old, overwrite
    fpaths = []

    log_level = logging.INFO
    for arg in args:
        if arg == "--delete":
            delete = True
        elif arg == "--delete-old":
            delete = delete_old = True
        elif arg == "--delete-old":
            overwrite = True
        elif arg == "--overwrite":
            overwrite = True
        elif arg == "-v":
            log_level = logging.DEBUG
            verbose = True
        else:
            fpaths.append(arg)

    frmt = "%(asctime)-15s:%(levelname)3.3s: %(message)s"
    logging.basicConfig(level=log_level, format=frmt)

    if not fpaths:
        fpaths.append('.')
    for f in fpaths:
        traverse_directory(f)

    log_unknown_keys()
    log_stats()

if __name__=='__main__':
    main(sys.argv[1:])
