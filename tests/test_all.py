"""
TestCases for teslacrack.

It needs a `bash` (cygwin or git-for-windows) because that was an easy way
to make files/dirs inaccessible, needed for TCs.
"""
from __future__ import print_function, unicode_literals

import argparse
import glob
import os
import sys
import textwrap
import unittest

import ddt
import yaml

import teslacrack
from unfactor import CrackException
import unfactor
import unfactor_bitcoin
import unfactor_ecdsa


app_db_txt = r"""
keys:
    - name     : ankostis
      type     : AES
      encrypted: 7097DDB2E5DD08950D18C263A41FF5700E7F2A01874B20F402680752268E43F4C5B7B26AF2642AE37BD64AB65B6426711A9DC44EA47FC220814E88009C90EA
      decrypted: 017b1647d4242bc67ce8a6aaec4d8b493f35519bd82775623d86182167148dd9
      factors  :
        - 2
        - 7
        - 97
        - 131
        - 14983
        - 28099
        - 4030421
        - 123985129
        - 2124553904704757231
        - 2195185826800714519
        - 5573636538860090464486823831839
        - 23677274243760534899430414029178304942110152493113248247
      crypted_files:
        - tesla2.pdf.vvv

    - name     : hermanndp
      type     : AES
      encrypted: 07E18921C536C112A14966D4EAAD01F10537F77984ADAAE398048F12685E2870CD1968FE3317319693DA16FFECF6A78EDBC325DDA2EE78A3F9DF8EEFD40299D9
      decrypted: 1b5c52aafcffda2e71001cf1880fe45cb93dea4c71328df595cb5eb882a3979f
      factors  :
        - 13
        - 3631
        - 129949621
        - 772913651
        - 7004965235626057660321517749245179
        - 4761326544374734107426225922123841005827557
        - 2610294590708970742101938252592668460113250757564649051
      crypted_files:
        - tesla_key3.doc.vvv
        - tesla_key3.pdf.zzz

    - name     : gh-14
      type     : BTC
      encrypted: 372AE820BBF2C3475E18F165F46772087EFFC7D378A3A4D10789AE7633EC09C74578993A2A7104EBA577D229F935AF77C647F18E113647C25EF19CC7E4EE3C4C
      decrypted: 38F47CB4BB4B0E2DA4AF771D618E9575520781F17E5785480F51B7955216D71F
      btc_addr : 1GSswEGHysnASUwNEKNjWXCW9vRCy57qA4
      factors  :
        - 2
        - 2
        - 3
        - 7
        - 11
        - 17
        - 19
        - 139
        - 2311
        - 14278309
        - 465056119273
        - 250220277466967
        - 373463829010805159059
        - 1261349708817837740609
        - 38505609642285116603442307097561327764453851349351841755789120180499
      crypted_files:
        - tesla_key14.jpg.vvv

    - name     : unknown1
      type     : AES
      encrypted: 5942f9a9aff
      factors  : [13, 3631, 129949621, 999999]
      error    : Extra factors given

    - name     : unknown2
      type     : AES
      encrypted: 5942f9a9aff
      factors  : [3631, 129949621]
      error    : Failed reconstructing AES-key!
      warning  : Incomplete factorization  ## UNUSED
"""

def read_app_db():
    return yaml.load(textwrap.dedent(app_db_txt))

app_db = read_app_db()


@ddt.ddt
class TUnfactor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(os.path.dirname(__file__))

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'AES'])
    def test_unfactor_from_file(self, key_rec):
        for f in key_rec.get('crypted_files', ()):
            exp_aes_key = key_rec.get('decrypted')
            if not exp_aes_key:
                continue
            factors = [int(fc) for fc in key_rec['factors']]
            aes_keys = unfactor.unfactor_key_from_file(f, factors)
            #print(key_rec['name'], f, aes_keys, exp_aes_key)
            self.assertIn(exp_aes_key, aes_keys,
                    (key_rec['name'], f, aes_keys, exp_aes_key))

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'AES'])
    def test_unfactor_key_failures(self, key_rec):
        name = key_rec['name']
        factors = [int(fc) for fc in key_rec['factors']]
        exp_aes_key = key_rec.get('decrypted')
        if not exp_aes_key:
            with self.assertRaises(CrackException, msg=key_rec) as cm:
                crypted_aes_key = int(key_rec['encrypted'], 16)
                unfactor.unfactor_key('<fpath>', factors, crypted_aes_key,
                        lambda *args: b'')
            err_msg = cm.exception.args[0]
            self.assertIn(key_rec['error'], err_msg, key_rec)


@ddt.ddt
class TUnfactorEcdsa(unittest.TestCase):
    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'BTC'])
    def test_unfactor_ecdsa_btc_from_file(self, key_rec):
        for f in key_rec.get('crypted_files', ()):
            exp_aes_key = key_rec.get('decrypted')
            if not exp_aes_key:
                continue
            factors = [int(fc) for fc in key_rec['factors']]
            aes_keys = unfactor_ecdsa.main(f, *factors)
            #print(key_rec['name'], f, aes_keys, exp_aes_key)
            self.assertIn(exp_aes_key, aes_keys,
                    (key_rec['name'], f, aes_keys, exp_aes_key))


@ddt.ddt
class TUnfactorBtc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(os.path.dirname(__file__))

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'BTC'])
    def test_unfactor_btc(self, key_rec):
        dec_key = key_rec.get('decrypted')
        btc_addr = key_rec.get('btc_addr')
        if btc_addr:
            factors = [int(fc) for fc in key_rec['factors']]
            dec_key = unfactor_bitcoin.main(btc_addr, *factors)
            #print(key_rec['name'], btc_addr, dec_key)
            self.assertIn(dec_key, dec_key, key_rec)


def chmod(mode, files):
    files = ' '.join("'%s'" % f for f in files)
    cmd = 'bash -c "chmod %s %s"' % (mode, files)
    ret = os.system(cmd)
    if ret:
        print("Bash-cmd `chmod` failed with: %s "
              "\n  TCs below may also fail, unless you mark manually `unreadable*` files!"
              % ret,
              file=sys.stderr)


class TTeslacrack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(os.path.dirname(__file__))
        ## Mark unreadable-files.
        chmod('115', glob.glob('unreadable*'))


    @classmethod
    def tearDownClass(cls):
        os.chdir(os.path.dirname(__file__))
        ## UNMark unreadable-files.
        chmod('775', glob.glob('unreadable*'))


    min_scanned_files = 16

    def setUp(self):
        """
        Delete all generated decrypted-files.

        Note that tests below should not modify git-files.
        """
        #
        skip_ext = ['.py', '.ccc', '.vvv', '.zzz']
        skip_files = ['bad_decrypted', 'README']
        for f in glob.glob('*'):
            if (os.path.isfile(f) and
                    os.path.splitext(f)[1] not in skip_ext and
                    not [sf for sf in skip_files if sf in f]):
                os.unlink(f)

    def test_statistics_normal(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        stats = teslacrack.teslacrack(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(
                badexisting_nfiles=1,
                badheader_nfiles=1,
                crypted_nfiles=12,
                decrypted_nfiles=6,
                deleted_nfiles=0,
                failed_nfiles=2,
                ndirs=-1,
                noaccess_ndirs=1,
                overwrite_nfiles=0,
                scanned_nfiles=-1,
                skip_nfiles=2,
                tesla_nfiles=14,
                unknown_nfiles=3,
                visited_ndirs=9)

        self.assertEquals(stats, exp_stats)


    def test_statistics_fix_dryrun(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        teslacrack.teslacrack(opts)
        opts.dry_run=True
        opts.fix=True
        stats = teslacrack.teslacrack(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(badexisting_nfiles=1,
                badheader_nfiles=1,
                crypted_nfiles=12,
                decrypted_nfiles=1,
                deleted_nfiles=0,
                failed_nfiles=2,
                ndirs=-1,
                noaccess_ndirs=1,
                overwrite_nfiles=1,
                scanned_nfiles=-1,
                skip_nfiles=7,
                tesla_nfiles=14,
                unknown_nfiles=3,
                visited_ndirs=9)
        self.assertEquals(stats, exp_stats)


    def test_statistics_overwrite_dryrun(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        teslacrack.teslacrack(opts)
        opts.dry_run=True
        opts.overwrite=True
        stats = teslacrack.teslacrack(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(badexisting_nfiles=0,
                    badheader_nfiles=1,
                    crypted_nfiles=12,
                    decrypted_nfiles=8,
                    deleted_nfiles=0,
                    failed_nfiles=2,
                    ndirs=-1,
                    noaccess_ndirs=1,
                    overwrite_nfiles=8,
                    scanned_nfiles=-1,
                    skip_nfiles=0,
                    tesla_nfiles=14,
                    unknown_nfiles=3,
                    visited_ndirs=9)
        self.assertEquals(stats, exp_stats)


    def test_statistics_delete_dryrun(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        teslacrack.teslacrack(opts)
        opts.dry_run=True
        opts.delete=True
        stats = teslacrack.teslacrack(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(badexisting_nfiles=1,
                badheader_nfiles=1,
                crypted_nfiles=12,
                decrypted_nfiles=0,
                deleted_nfiles=0,
                failed_nfiles=2,
                ndirs=-1,
                noaccess_ndirs=1,
                overwrite_nfiles=0,
                scanned_nfiles=-1,
                skip_nfiles=8,
                tesla_nfiles=14,
                unknown_nfiles=3,
                visited_ndirs=9)
        self.assertEquals(stats, exp_stats)


    def test_statistics_delete_old_dryrun(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        teslacrack.teslacrack(opts)
        opts.dry_run=True
        opts.delete_old=True
        stats = teslacrack.teslacrack(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(badexisting_nfiles=1,
                    badheader_nfiles=1,
                    crypted_nfiles=12,
                    decrypted_nfiles=0,
                    deleted_nfiles=8,
                    failed_nfiles=2,
                    ndirs=-1,
                    noaccess_ndirs=1,
                    overwrite_nfiles=0,
                    scanned_nfiles=-1,
                    skip_nfiles=8,
                    tesla_nfiles=14,
                    unknown_nfiles=3,
                    visited_ndirs=9)
        self.assertEquals(stats, exp_stats)


