"""
TeslaCrack - decryptor for the TeslaCrypt ransomware

by Googulator

   python teslacrypt.py [options] [file-path-1]...

When invoked without any folder specified, working-dir('.') assumed.

 OPTIONS

   --delete       # Delete encrypted-files after decrypting them.
   --delete-old   # Delete encrypted even if decrypted-file created during a previous run.
   --overwrite    # Re-decrypt and overwirte existing decrypted-files.
   --progress     # Before start encrypting, pre-scan all dirs, to provide progress-indicator.
   -v, --verbose  # Log(DEBUG) all files as they are being decrypted.
   -n, --dry-run  # Decrypt but don't Write/Delete files, just report actions performed.

EXAMPLES:

   python teslacrack -v                      ## Decrypts current-folder, logging verbosely.
   python teslacrack .  bar\cob.xlsx         ## Decrypts current-folder & file
   python teslacrack --delete-old C:\\       ## WILL DELETE ALL `.vvv` files on disk!!!
   python teslacrack --progress -n -v  C:\\  ## Just to check what actions will perform.

NOTES:

This script requires pycrypto to be installed.

To use, factor the 2nd hex string found in the headers of affected files using msieve.
The AES-256 key will be one of the factors, typically not a prime - experiment to see which one works.
Insert the hex string & AES key below, under known_keys, then run on affected directory.
If an unknown key is reported, crack that one using msieve, then add to known_keys and re-run.

Enjoy! ;)
"""

from __future__ import unicode_literals

import argparse
import logging
import os
import shutil
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

## Add more known extensions, e.g. '.xyz'.
#  Note that '.xxx', '.micro' and '.ttt' are encrypted by a new variant
#  of teslacrypt (3.0).
tesla_extensions = ['.vvv', '.ccc',  '.zzz', '.aaa', '.abc']

## If i18n-filenames are destroyed, experiment with this.
#  e.g. 'UTF-8', 'iso-8859-9', 'CP437', 'CP1252'
filenames_encoding = sys.getfilesystemencoding()

known_file_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

unknown_keys = {}
unknown_btkeys = {}

PROGRESS_INTERVAL_SEC = 7 # Log stats every that many files processed.
_last_progress_time = time.time()


_PY2 = sys.version_info[0] == 2


def fix_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key


def _decide_ext(ext):
    """Strange logic here, see :func:`_argparse_ext_type()`."""
    if not ext or isinstance(ext, bool):
        ext = None
    return ext


def needs_decryption(fname, exp_size, fix, overwrite):
    """Returns (file_exist?  should_decrypt?  what_backup_ext?)."""
    fexists = os.path.isfile(fname)
    if overwrite:
        should_decrypt = overwrite
    elif fexists:
        disk_size = os.stat(fname).st_size
        if disk_size != exp_size:
            log.warn("Bad(?) decrypted-file had unexpected size(disk_size(%i) != %i): %s",
                    disk_size, exp_size, fname)
            should_decrypt = fix
        else:
            should_decrypt = False
    else:
        should_decrypt = True
    return fexists, should_decrypt, _decide_ext(should_decrypt)


def decrypt_file(opts, stats, fpath):
    try:
        stats.visited_nfiles += 1
        if not os.path.splitext(fpath)[1] in tesla_extensions:
            return

        stats.encrypt_nfiles += 1
        do_unlink = False
        with open(fpath, "rb") as fin:
            header = fin.read(414)

            if header[:5] not in known_file_magics:
                log.info("File %r doesn't appear to be TeslaCrypted.", fpath)
                stats.skip_nfiles += 1
                return

            aes_encrypted_key = header[0x108:0x188].rstrip(b'\0')
            if aes_encrypted_key not in known_keys:
                if aes_encrypted_key not in unknown_keys:
                    unknown_keys[aes_encrypted_key] = fpath
                btc_key = header[0x45:0xc5].rstrip(b'\0')
                if btc_key not in unknown_btkeys:
                    unknown_btkeys[btc_key] = fpath
                log.warn("Unknown key in file: %s", fpath)
                stats.unknown_nfiles += 1
                return


            size = struct.unpack('<I', header[0x19a:0x19e])[0]
            orig_fname = os.path.splitext(fpath)[0]
            decrypt_exists, should_decrypt, backup_ext = needs_decryption(
                    orig_fname, size, opts.fix, opts.overwrite)
            if should_decrypt:
                if decrypt_exists and backup_ext:
                    log.debug("Backing-up: %s --> %s", orig_fname, backup_ext)
                    backup_fname = orig_fname + backup_ext
                    opts.dry_run or shutil.move(orig_fname, backup_fname)
                log.debug("Decrypting%s%s: %s",
                        '(overwrite)' if decrypt_exists else '',
                        '(dry-run)' if opts.dry_run else '', fpath)
                decryptor = AES.new(
                        fix_key(known_keys[aes_encrypted_key]),
                        AES.MODE_CBC, header[0x18a:0x19a])
                data = decryptor.decrypt(fin.read())[:size]
                if not opts.dry_run:
                    with open(orig_fname, 'wb') as fout:
                        fout.write(data)
                if opts.delete and not decrypt_exists or opts.delete_old:
                    do_unlink = True
                stats.decrypt_nfiles += 1
                stats.overwrite_nfiles += decrypt_exists
            else:
                log.debug("Skip %r, already decrypted.", fpath)
                stats.skip_nfiles += 1
                if opts.delete_old:
                    do_unlink = True
        if do_unlink:
            log.debug("Deleting%s: %s",
                    '(dry-run)' if opts.dry_run else '', fpath)
            opts.dry_run or os.unlink(fpath)
            stats.deleted_nfiles += 1
    except Exception as e:
        stats.failed_nfiles += 1
        log.error("Error decrypting %r due to %r!  Please try again.",
                fpath, e, exc_info=opts.verbose)


def is_progess_time():
    global _last_progress_time
    if time.time() - _last_progress_time > PROGRESS_INTERVAL_SEC:
        _last_progress_time = time.time()
        return True


def traverse_fpaths(opts, stats):
    """Scan disk and decrypt tesla-files.

    :param: list fpaths:
            Start points to scan.
            Must be unicode, and on *Windows* '\\?\' prefixed.
    """
    for fpath in opts.fpaths:
        if os.path.isfile(fpath):
            decrypt_file(opts, stats, fpath)
        else:
            for dirpath, _, files in os.walk(fpath):
                stats.visited_ndirs += 1
                if is_progess_time():
                    log_stats(stats, dirpath)
                    log_unknown_keys()
                for f in files:
                    decrypt_file(opts, stats, os.path.join(dirpath, f))


def count_subdirs(opts, stats):
    n = 0
    log.info("+++Counting dirs...")
    for f in opts.fpaths:
        #f = upath(f) # Don't bother...
        for _ in os.walk(f):
            if is_progess_time():
                log.info("+++Counting dirs: %i...", n)
            n += 1
    return n


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


def log_stats(stats, fpath=''):
    if fpath:
        fpath = ': %r' % os.path.dirname(fpath)
    dir_progress = ''
    if stats.ndirs > 0:
        prcnt = 100 * stats.visited_ndirs / stats.ndirs
        dir_progress = ' of %i(%0.2f%%)' % (stats.ndirs, prcnt)
    log.info("+++Dir %5i%s%s"
            "\n    visited: %7i"
            "\n  encrypted:%7i"
            "\n    decrypted:%7i"
            "\n    overwritten:%7i"
            "\n      deleted:%7i"
            "\n      skipped:%7i"
            "\n      unknown:%7i"
            "\n       failed:%7i",
        stats.visited_ndirs, dir_progress, fpath, stats.visited_nfiles, stats.encrypt_nfiles,
        stats.decrypt_nfiles, stats.overwrite_nfiles, stats.deleted_nfiles,
        stats.skip_nfiles, stats.unknown_nfiles, stats.failed_nfiles)



def _path_to_ulong(path):
    """Support Long Unicode paths and handle `C: --> C:\<current-dir>` on *Windows*."""
    if _PY2:
        path = unicode(path, filenames_encoding)  # @UndefinedVariable
    if os.name == 'nt' or sys.platform == 'cygwin': ## But cygwin is missing cryptodome lib.
        if path.endswith(':'):
            path += '\\'
        path = r'\\?\%s' % os.path.abspath(path)
    return path


def _argparse_ext_type(ext):
    ext = ext.strip()
    if ext == '': # User wanted option enabled, but without .ext.
        ext = True
    elif not ext.startswith('.'):
        raise argparse.ArgumentTypeError(
                "Extension %r must start with a dot(`.`) or '' for None!" % ext)
    return ext


def _parse_args(args):
    doclines = __doc__.split('\n')
    ap = argparse.ArgumentParser(description='\n'.join(doclines[:4]),
            epilog='\n'.join(doclines[-12:]))
    ap.add_argument('-v', '--verbose', action='store_true',
            help="Verbosely log(DEBUG) all files decrypted.")
    ap.add_argument('-n', '--dry-run', action='store_true',
            help="Decrypt but don't Write/Delete files, just report actions performed "
            "[default: %(default)r].")
    ap.add_argument('--delete', action='store_true',
            help="Delete encrypted-files after decrypting them.")
    ap.add_argument('--delete-old', action='store_true',
            help="Delete encrypted even if decrypted-file created during a previous run "
            "[default: %(default)r].")
    ap.add_argument('--progress', action='store_true',
            help="Before start encrypting, pre-scan all dirs, to provide progress-indicator "
            "[default: %(default)r].")
    ap.add_argument('fpaths', nargs='*', default=['.'],
            help="Decrypt but don't Write/Delete files, just report actions performed "
            "[default: %(default)r].")
    ap.add_argument('--version', action='version', version='%(prog)s 2.0')
    xgroup = ap.add_mutually_exclusive_group()
    xgroup.add_argument('--fix', nargs='?', type=_argparse_ext_type, metavar='<.ext>', default=False, const='.BAK',
            help="Re-decrypt tesla-files and overwrite decrypted-counterparts if they have unexpected size. "
            "By default, backs-up existing files with '%(const)s' extension. "
            "Specify empty('') extension for no backup (eg. `--fix=`) "
            "WARNING: You may LOOSE FILES that have changed due to regular use, "
            "such as, configuration-files and mailboxes! "
            "[default: %(default)s]. ")
    xgroup.add_argument('--overwrite', nargs='?', type=_argparse_ext_type, metavar='<.ext>', default=False, const=True,
            help="Re-decrypt ALL tesla-files, overwritting all decrypted-counterparts. "
            "Optionally creates backups with the given extension. "
            "WARNING: You may LOOSE FILES that have changed due to regular use, "
            "such as, configuration-files and mailboxes! "
            "[default: %(default)s]. ")
    return ap.parse_args(args)


def main(args):
    opts = _parse_args(args)

    log_level = logging.DEBUG if opts.verbose else logging.INFO
    frmt = "%(asctime)-15s:%(levelname)3.3s: %(message)s"
    logging.basicConfig(level=log_level, format=frmt)
    log.debug('Options: %s', opts)

    opts.fpaths = [_path_to_ulong(f) for f in opts.fpaths]

    stats = argparse.Namespace(ndirs = -1,
            visited_ndirs=0, visited_nfiles=0, encrypt_nfiles=0, decrypt_nfiles=0,
            overwrite_nfiles=0, deleted_nfiles=0, skip_nfiles=0, unknown_nfiles=0,
            failed_nfiles=0, )

    if opts.progress:
        stats.ndirs = count_subdirs(opts, stats)
    traverse_fpaths(opts, stats)

    log_unknown_keys()
    log_stats(stats)

if __name__=='__main__':
    main(sys.argv[1:])
