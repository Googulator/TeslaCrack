"""
TeslaCrack - decryptor for the TeslaCrypt ransomware

by Googulator

USAGE: teslacrack.py [-h] [-v] [-n] [--delete] [--delete-old] [--progress]
                     [--version] [--fix [<.ext>] | --overwrite [<.ext>]]
                     [fpaths [fpaths ...]]

TeslaCrack - decryptor for the TeslaCrypt ransomware by Googulator

positional arguments:
  fpaths                Decrypt but don't Write/Delete files, just report
                        actions performed [default: ['.']].

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbosely log(DEBUG) all actions on files decrypted.
  -n, --dry-run         Decrypt but don't Write/Delete files, just report
                        actions performed [default: False].
  --delete              Delete crypted-files after decrypting them.
  --delete-old          Delete crypted even if decrypted-file created during a
                        previous run [default: False].
  --progress            Before start decrypting files, pre-scan all dirs, to
                        provide progress-indicator [default: False].
  --version             show program's version number and exit
  --fix [<.ext>]        Re-decrypt tesla-files and overwrite crypted-
                        counterparts if they have unexpected size. By default,
                        backs-up existing files with '.BAK' extension. Specify
                        empty('') extension for no backup (eg. `--fix=`)
                        WARNING: You may LOSE FILES that have changed due to
                        regular use, such as, configuration-files and
                        mailboxes! [default: False].
  --overwrite [<.ext>]  Re-decrypt ALL tesla-files, overwritting all crypted-
                        counterparts. Optionally creates backups with the
                        given extension. WARNING: You may LOSE FILES that
                        have changed due to regular use, such as,
                        configuration-files and mailboxes! [default: False].

EXAMPLES:

   python teslacrack -v                      ## Decrypt current-folder, logging verbosely.
   python teslacrack .  bar\cob.xlsx         ## Decrypt current-folder & file
   python teslacrack --delete-old C:\\       ## WILL DELETE ALL `.vvv` files on disk!!!
   python teslacrack --progress -n -v  C:\\  ## Just to check what actions will perform.

NOTES:

This script requires pycrypto to be installed.

To use, factor the 2nd hex string found in the headers of affected files using msieve.
The AES-256 key will be one of the factors, typically not a prime - experiment to see which one works.
Insert the hex string & AES key below, under known_AES_key_pairs, then run on affected directory.
If an unknown key is reported, crack that one using msieve, then add to known_AES_key_pairs and re-run.

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
import binascii


log = logging.getLogger('teslacrack')

## Add your (encrypted-AES-key: reconstructed-AES-key) pair(s) here,
#  like the examples below:
#
known_AES_key_pairs = {
    b'D4E0010A8EDA7AAAE8462FFE9562B29871B9DA186D98B5B15EC9F77803B60EAB12ADDF78CBD4D9314A0C31270CC8822DCC071D10193D1E612360B26582DAF124': 'ea685a3cdb780df212ebaa5003adc3e104063ebc259352c50988b7561ad134a5',
    b'9F2874FB536C0A6EF7B296416A262A8A722A38C82EBD637DB3B11232AE0102153C18837EFB4558E9E2DBFC1BB4BE799AE624ED717A234AFC5E2F8E2668C76B6C': 'cd0d0d54c4fdb7647c4db0956a3046c34e385b51d735d17c009d473e02842795',
    b'115DF08B0956AEDF0293EBA00CCD6793344D6590D234FE0DF2E679B7159E8DB05F960455F17CDDCE094420182484E73D4041C39531B5B8E753E562910561DE52': '1adc91333e8f6b59bbcfb33451d8a3a94d14b38415fa33c0f7fb695920d3618f',
    b'7097DDB2E5DD08950D18C263A41FF5700E7F2A01874B20F402680752268E43F4C5B7B26AF2642AE37BD64AB65B6426711A9DC44EA47FC220814E88009C90EA': '017b1647d4242bc67ce8a6aaec4d8b493f35519bd82775623d86182167148dd9',
    b'07E18921C536C112A14966D4EAAD01F10537F77984ADAAE398048F12685E2870CD1968FE3317319693DA16FFECF6A78EDBC325DDA2EE78A3F9DF8EEFD40299D9': '1b5c52aafcffda2e71001cf1880fe45cb93dea4c71328df595cb5eb882a3979f',
    b'10043D7DA5E5BDF7BF22928744246CC121DB50223E91AEEDDBF6DE23606711E3EF956F19CECFC380E58030B988177A268C402DDBC5B44A590DE8A06AA13EAF1D': 'af08733b6871edccf9bf12a0b36333eb20937a82ae7cf8d20cd6603017ea518d',
}

## Add more known extensions, e.g. '.xyz'.
#  Note that '.xxx', '.micro' and '.ttt' are crypted by a new variant
#  of teslacrypt (3.0).
tesla_extensions = ['.vvv', '.ccc',  '.zzz', '.aaa', '.abc']
tesla_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

## If i18n-filenames are destroyed, experiment with this.
#  e.g. 'UTF-8', 'iso-8859-9', 'CP437', 'CP1252'
filenames_encoding = sys.getfilesystemencoding()


unknown_keys = {}
unknown_btkeys = {}

PROGRESS_INTERVAL_SEC = 3 # Log stats every that many files processed.
_last_progress_time = 0#time.time()


_PY2 = sys.version_info[0] == 2


def lalign_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key

def fix_hex_key(hex_key):
    return lalign_key(binascii.unhexlify(hex_key))

def _decide_backup_ext(ext):
    """Strange logic here, see :func:`_argparse_ext_type()`."""
    if not ext or isinstance(ext, bool):
        ext = None
    return ext


def _needs_decrypt(fname, exp_size, fix, overwrite, stats):
    """Returns (file_exist?  should_decrypt?  what_backup_ext?)."""
    decrypted_exists = os.path.isfile(fname)
    if overwrite:
        should_decrypt = overwrite
    elif decrypted_exists:
        disk_size = os.stat(fname).st_size
        if disk_size != exp_size:
            log.warn("Bad(?) decrypted-file %r had unexpected size(disk_size(%i) != %i)! "
                    "\n  Will be overwritten: %s",
                    fname, disk_size, exp_size, bool(fix))
            stats.badexisting_nfiles += 1
            should_decrypt = fix
        else:
            should_decrypt = False
    else:
        should_decrypt = True
    return decrypted_exists, should_decrypt, _decide_backup_ext(should_decrypt)


def decrypt_file(opts, stats, crypted_fname):
    do_unlink = False
    try:
        with open(crypted_fname, "rb") as fin:
            header = fin.read(414)

            if header[:5] not in tesla_magics:
                log.info("File %r doesn't appear to be TeslaCrypted.", crypted_fname)
                stats.badheader_nfiles += 1
                return
            stats.crypted_nfiles += 1

            aes_crypted_key = header[0x108:0x188].rstrip(b'\0')
            aes_key = known_AES_key_pairs.get(aes_crypted_key)
            if not aes_key:
                if aes_crypted_key not in unknown_keys:
                    unknown_keys[aes_crypted_key] = crypted_fname
                btc_key = header[0x45:0xc5].rstrip(b'\0')
                if btc_key not in unknown_btkeys:
                    unknown_btkeys[btc_key] = crypted_fname
                log.warn("Unknown key: %s \n  in file: %s",
                        aes_crypted_key, crypted_fname)
                stats.unknown_nfiles += 1
                return


            size = struct.unpack('<I', header[0x19a:0x19e])[0]
            decrypted_fname = os.path.splitext(crypted_fname)[0]
            decrypted_exists, should_decrypt, backup_ext = _needs_decrypt(
                    decrypted_fname, size, opts.fix, opts.overwrite, stats)
            if should_decrypt:
                crypted_mtime = os.path.getmtime(crypted_fname)
                crypted_atime = os.path.getatime(crypted_fname)
                log.debug("decrypting%s%s%s: %s",
                        '(overwrite)' if decrypted_exists else '',
                        '(backup)' if decrypted_exists and backup_ext else '',
                        '(dry-run)' if opts.dry_run else '', crypted_fname)
                if decrypted_exists and backup_ext:
                    backup_fname = decrypted_fname + backup_ext
                    opts.dry_run or shutil.move(decrypted_fname, backup_fname)
                decryptor = AES.new(
                        fix_hex_key(aes_key),
                        AES.MODE_CBC, header[0x18a:0x19a])
                data = decryptor.decrypt(fin.read())[:size]
                if not opts.dry_run:
                    with open(decrypted_fname, 'wb') as fout:
                        fout.write(data)
                    os.utime(decrypted_fname,(crypted_atime,crypted_mtime))
                if opts.delete and not decrypted_exists or opts.delete_old:
                    do_unlink = True
                stats.decrypted_nfiles += 1
                stats.overwrite_nfiles += decrypted_exists
            else:
                log.debug("Skip %r, already decrypted.", crypted_fname)
                stats.skip_nfiles += 1
                if opts.delete_old:
                    do_unlink = True
    except Exception as e:
        stats.failed_nfiles += 1
        log.error("Error decrypting %r due to %r!  Please try again.",
                crypted_fname, e, exc_info=opts.verbose)

    if do_unlink:
        try:
            log.debug("Deleting%s: %s",
                    '(dry-run)' if opts.dry_run else '', crypted_fname)
            opts.dry_run or os.unlink(crypted_fname)
            stats.deleted_nfiles += 1
        except Exception as e:
            stats.failed_nfiles += 1
            log.warn("Error deleting %r due to %r!.",
                    crypted_fname, e, exc_info=opts.verbose)


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
    def handle_bad_subdir(err):
        stats.noaccess_ndirs += 1
        log.error('%r: %s' % (err, err.filename))

    def scan_file(fname):
        if os.path.splitext(fname)[1] in tesla_extensions:
            stats.tesla_nfiles += 1
            decrypt_file(opts, stats, fname)

    for fpath in opts.fpaths:
        if os.path.isfile(fpath):
            scan_file(fpath)
        else:
            for dirpath, _, files in os.walk(fpath, onerror=handle_bad_subdir):
                stats.visited_ndirs += 1
                stats.scanned_nfiles += len(files)
                if is_progess_time():
                    log_stats(stats, dirpath)
                    log_unknown_keys()
                for f in files:
                    scan_file(os.path.join(dirpath, f))


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
            "\n       scanned: %7i"
            "\n  noAccessDirs: %7i"
            "\n      teslaExt:%7i"
            "\n       badheader:%7i"
            "\n         crypted:%7i"
            "\n         decrypted:%7i"
            "\n           skipped:%7i"
            "\n           unknown:%7i"
            "\n            failed:%7i"
            "\n\n       overwritten:%7i"
            "\n       badExisting:%7i"
            "\n           deleted:%7i"
        , stats.visited_ndirs, dir_progress, fpath, stats.scanned_nfiles,
        stats.noaccess_ndirs, stats.tesla_nfiles, stats.badheader_nfiles,
        stats.crypted_nfiles, stats.decrypted_nfiles, stats.skip_nfiles,
        stats.unknown_nfiles, stats.failed_nfiles, stats.overwrite_nfiles,
        stats.badexisting_nfiles, stats.deleted_nfiles)

def _path_to_ulong(path):
    """Support Long Unicode paths and handle `C: --> C:\<current-dir>` on *Windows*."""
    win_prefix = '\\\\?\\'
    if _PY2:
        try:
            path = unicode(path, filenames_encoding)  # @UndefinedVariable
        except:
            pass
    if os.name == 'nt' or sys.platform == 'cygwin':  ## But cygwin is missing cryptodome lib.
        if path.endswith(':'): ## Avoid Windows's per-drive "remembered" cwd.
            path += '\\'
        if not path.startswith(win_prefix):
            path = win_prefix + os.path.abspath(path)
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
            help="Verbosely log(DEBUG) all actions on files decrypted.")
    ap.add_argument('-n', '--dry-run', action='store_true',
            help="Decrypt but don't Write/Delete files, just report actions performed "
            "[default: %(default)r].")
    xgroup_delete = ap.add_mutually_exclusive_group()
    xgroup_delete.add_argument('--delete', action='store_true',
            help="Delete crypted-files after decrypting them.")
    xgroup_delete.add_argument('--delete-old', action='store_true',
            help="Delete crypted even if decrypted-file created during a previous run "
            "[default: %(default)r].")
    ap.add_argument('--progress', action='store_true',
            help="Before start decrypting files, pre-scan all dirs, to provide progress-indicator "
            "[default: %(default)r].")
    ap.add_argument('fpaths', nargs='*', default=['.'],
            help="Decrypt but don't Write/Delete files, just report actions performed "
            "[default: %(default)r].")
    ap.add_argument('--version', action='version', version='%(prog)s 2.0')
    xgroup_overwrite = ap.add_mutually_exclusive_group()
    xgroup_overwrite.add_argument('--fix', nargs='?',
            type=_argparse_ext_type, metavar='<.ext>', default=False, const='.BAK',
            help="Re-decrypt tesla-files and overwrite crypted-counterparts if they have unexpected size. "
            "By default, backs-up existing files with '%(const)s' extension. "
            "Specify empty('') extension for no backup (eg. `--fix=`) "
            "WARNING: You may LOSE FILES that have changed due to regular use, "
            "such as, configuration-files and mailboxes! "
            "[default: %(default)s]. ")
    xgroup_overwrite.add_argument('--overwrite', nargs='?',
            type=_argparse_ext_type, metavar='<.ext>', default=False, const=True,
            help="Re-decrypt ALL tesla-files, overwritting all crypted-counterparts. "
            "Optionally creates backups with the given extension. "
            "WARNING: You may LOSE FILES that have changed due to regular use, "
            "such as, configuration-files and mailboxes! "
            "[default: %(default)s]. ")
    return ap.parse_args(args)


def teslacrack(opts):
    opts.fpaths = [_path_to_ulong(f) for f in opts.fpaths]

    stats = argparse.Namespace(ndirs = -1,
            visited_ndirs=0, scanned_nfiles=0, noaccess_ndirs=0,
            tesla_nfiles=0, crypted_nfiles=0, decrypted_nfiles=0, badheader_nfiles=0,
            skip_nfiles=0, unknown_nfiles=0, failed_nfiles=0, deleted_nfiles=0,
            overwrite_nfiles=0, badexisting_nfiles=0)

    if opts.progress:
        stats.ndirs = count_subdirs(opts, stats)
    traverse_fpaths(opts, stats)

    log_unknown_keys()
    log_stats(stats)

    return stats

def main(*args):
    """Parse args, setup logging and delegate to :func:`teslacrack()`."""
    if not args:
        args = sys.argv
    opts = _parse_args(args[1:])

    log_level = logging.DEBUG if opts.verbose else logging.INFO
    frmt = "%(asctime)-15s:%(levelname)3.3s: %(message)s"
    logging.basicConfig(level=log_level, format=frmt)
    log.debug('Options: %s', opts)
    teslacrack(opts)

if __name__=='__main__':
    main()
