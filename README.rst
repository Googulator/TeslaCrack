##########################################################
TeslaCrack - decrypt files crypted by TeslaCrypt ransomware
##########################################################
|pypi-ver| |flattr-donate| |btc-donate|

:Date:        2016-01-22
:Source:      https://github.com/Googulator/TeslaCrack
:Author:      Googulator


This is a tool for decrypting files that were crypted with the latest version
(variously known as "v8" or "v2.2.0") of the **TeslaCrypt ransomware**.
This new version can be recognized from the extensions ``.vvv, .ccc,  .zzz, .aaa, .abc``
added to the names of you original files, and/or the filenames of the ransom notes
being ``Howto_RESTORE_FILES.txt``.

The tool should also work against other recent versions of TeslaCrypt -
for ancient versions, use *tesladecrypt* or *TeslaDecoder* together with
the Bitcoin-based key reconstructor instead (``unfactor_bitcoin.py``).

.. contents:: Table of Contents
  :backlinks: top

Overview
========
We recapitulate `how TeslaCrypt ransomware works and explain the weakness
<http://www.bleepingcomputer.com/news/security/teslacrypt-decrypted-flaw-in-teslacrypt-allows-victims-to-recover-their-files/>`_
that is relevant for this cracking tool:

1. *TeslaCrypt* creates a symmetrical AES-session-key that will be used to
   encrypt your files,
2. it then asymmetrically ECDH-encrypts that AES-key and transmits the private-ECDH-key
   to the operators of the ransomware (but that is irrelevant here), and finally
3. it starts crypting your files one-by-one, attaching the encrypted-AES-key
   into their header.

- Multiple AES-keys are generated if you interrupt the ransomware while it crypts
  your files (i.e. reboot).

*TeslaCrack* implements (primarily) an integer factorization attack against
the asymmetric scheme (breaking the encrypted-AES-key).
The actual factorization is not implemented within *TeslaCrack*, instead,
it extracts the numbers to be factored, that you have to feed them into
3rd party factoring tools, such as `YAFU or msieve
<https://www.google.com/search?q=msieve+factorization>`_.

The files performing most of the job are these two:

- ``teslacrack.py``: parses the headers from the tesla-files,
  extracts their encrypted-AES-keys, and if their corresponding decrypted-key
  has already been reconstructed earlier (by following the steps described below),
  and decrypts files.
- ``unfactor.py``: reconstructs an AES-key from a factorized(externally)
  encrypted-AES-key.


Installation
============

You need a working Python 2.7 or Python-3.4+ environment,
**preferably 64-bit** (if supported by your OS).
A 32-bit Python can also work, but it will be significantly slower

Install Python
--------------
In *Windows*, the following 1 + 2 alternative have been tested:

- The `"official" distributions <https://www.python.org>`_, which **require
  admin-rights to install and to ``pip``-install the necessary packages.**
  Note the official site by default may offer you a 32-bit version -
  choose explicitly the 64-bit version.
  Check also the option for adding Python into your ``PATH``.

- The portable `WinPython <https://winpython.github.io>`_ distributions.
  It has been tested both with: `WinPython-3.4 "slim"
  <http://sourceforge.net/projects/winpython/files/WinPython_3.4/3.4.3.7/>`_
  and `WinPython-2.7 <http://sourceforge.net/projects/winpython/files/WinPython_2.7/2.7.10.3/>`_.
  Notice that by default they do not modify your ``PATH`` so you
  **must run all commands from the included command-prompt executable**.
  And although  they **do not require admin-rights to install**,
  you most probably **need admin-rights** when running `teslacrack.py`,
  if the files to decrypt originate from a different user.

Install TeslaCrack
------------------
1. At a command-prompt with python enabled (and with admin-rights in the "official" distribution),
   execute the following commands::

       pip install pycryptodome
       pip install ecdsa                REM optional, needed only for unfactor_ecdsa.py
       pip install pybitcoin            REM optional, needed only for unfactor_bitcoin.py

   - If you get an error like ``'pip' is not recognized as an internal or external command ...``
     then you may execute the following Python-2 code and re-run the commands above::

         python -c "import urllib2; exec urllib2.urlopen('https://bootstrap.pypa.io/get-pip.py').read()"


2. In addition, you need a program for factoring large numbers.

   For this purpose, I recommend using Msieve (e.g. http://sourceforge.net/projects/msieve/)
   and the ``factmsieve.py`` wrapper.
   Run the factorization on a fast computer, as it can take a lot of processing power.
   On a modern dual-core machine, most encrypted AES-keys can be factorized
   in a few hours, with some unlucky keys possibly taking up to a week.


How to decrypt your files
=========================
Note that commands below assume that your *working folder* is the one
containing ``unfactor.py`` and ``teslacrack.py`` files.


1. Collect a "crypted" file from the attacked machine in your *working folder*.
   Choose a file with known magic-bytes - ``unfactor.py`` has been pre-configured
   with some common data-formats to choose from:

   - *pdf* & *word-doc* files,
   - images and sounds (*jpg, png, gif, mp3*), and
   - archive formats: *gzip, bz2, 7z, rar* and of course *zip*, which includes
     all LibreOffice and newer Microsoft *docs/xlsx* & *ODF* documents.

   .. Tip::
       To view or extend the supported formats, edit ``unfactor.py`` and append
       a new mapping into ``known_file_magics`` dictionary.  Note that
       in *python-3*, bytes are given like that: ``b'\xff\xd8'``.

2. If the your crypted files do not have one of the known extensions,
   ``.vvv, .ccc, .zzz, .aaa, .abc``, edit ``teslacrack.py`` to append it
   into ``tesla_extensions`` string-list.

   .. Note::
        The extensions '.xxx', '.micro', '.mp3' and '.ttt' have been reported for new
        variants of TeslaCrypt (3.0 and 4.0), and this tool cannot decrypt them, anyway. Please use TeslaDecoder instead, with 440A241DD80FCC5664E861989DB716E08CE627D8D40C7EA360AE855C727A49EE as the key.

3. Enter this command in your working folder to process your crypted file
   (notice the ``.`` at the end,; you may use the name of your crypted file instead)::

       python teslacrack.py -v .

   It will print out two hex numbers.  **The first number is your encrypted-AES-key**.

   - If you get an error message, make sure that you have Python and *pycryptodome* installed
     (see instructions above).

4. Convert your hexadecimal AES-key to decimal, e.g. in python use ``int('859091953186ed67326657c9c42efa88d770fc2512a9e37ab811b4c919a82c8aeec9b6ebb5e6effd559aedcff2d49018d268950eccd0e7603b2e22ea214ff365', 16)``,
   and search `factordb.com <http://factordb.com/>`_ for this number. If you are lucky,
   it may have been already factored, and you can skip the next step :-)

5. Factor the AES key printed by ``teslacrack.py`` above:

   - Using *msieve*::

         msieve -v -e 0x\<encrypted-AES key from teslacrack.py>

     The ``-e`` switch is needed to do a "deep" elliptic curve search,
     which speeds up *msieve* for numbers with many factors (by default,
     *msieve* is optimized for semiprimes such as RSA moduli)

   - Alternatively, you can use *YAFU*, which is multithreaded, but
     tends to crash often (at least for me)
     If you use *YAFU*, make sure to run it from command line using
     the ``-threads`` option!

   - For numbers with few factors (where ``-e`` is ineffective, and *msieve/YAFU*
     run slow), use ``factmsieve.py`` (downloaded optionally above), which is
     more complicated, but also faster, multithreaded, and doesn't tend to crash.

6. To reconstruct the AES-key that has crypted your files, run::

       python unfactor.py  <crypted file>  <primes from previous step, separated by spaces>

   It will reconstruct and print any decrypted AES-keys candidates (usually just one).

   - You may use ``unfactor_ecdsa.py`` to recover your keys - this is slower,
     and requires the *ecdsa* Python module to be installed; however,
     unlike ``unfactor.py``, it can also reconstruct Bitcoin private-keys
     (to be used with TeslaDecoder), not just AES ones. Also, ``unfactor_ecdsa.py``
     is guaranteed to always yield only correct keys, and can recover keys
     even from files without known magic numbers, while ``unfactor.py`` is
     filetype-dependent, and may sometimes report false positive keys.
     The syntax for the two scripts is the same, simply add ``_ecdsa``
     to the name of the script.

   - For very old TeslaCrypt infections, a third key reconstructor is provided,
     ``unfactor_bitcoin.py``, which uses the Bitcoin ransom address instead
     of a sample file.
     Both the Bitcoin address and the public key can be obtained from the recovery file
     in the affected machine's Documents folder for such old infections.
     The Bitcoin address is the first line of the file, while the public key
     (which needs to be factored) is the third line.
     The syntax is like ``unfactor.py``, but use the Bitcoin address in place of a filename.
     Note that ``teslacrack.py`` can't decode the file format used by old TeslaCrypt,
     so you will need to perform the actual decryption using *TeslaDecoder*.

   - Archives, such as *zip* files and *docx/xlsx/odf* documents may
     fail to produce a key, when irrelevant bytes have been prepended - this is
     allowed by their format.  Repeate this step with another type of file.


7. Edit ``teslacrack.py`` to add a new key-pair into the ``known_AES_key_pairs``
   dictionary, like that::

      <encrypted-AES-key>: <1st decrypted-AES-key candidate>,

8. Repeat step 3. A decrypted file should now appear next to the crypted one
   (``.vvv`` or ``.ccc``, etc) - verify that the contents of the decrypted-file
   do make sense.

   - If not, redo step 7, replacing every time a new candidate decrypted AES-key
     in the pair.

9. To decrypt all of your files run from an administrator command prompt::

        python teslacrack.py --progress D:\\

   - In some cases you may start receiving error-messages, saying
     ``"Unknown key in file: some/file"``.
     This means that some of your files have been crypted with different
     AES-keys (i.e. the ransomware had been restarted due to a reboot).
     ``teslacrack.py`` will print at the end any new encrypted AES-key(s)
     encountered - repeat the procedure from step 4 for all newly discovered
     key(s) :-(

   - ``teslacrack.py`` accepts an optional ``--delete`` and ``--delete-old``
     parameters, which will delete the crypted-files of any cleartext file it
     successfully generates (or already has generated, for the 2nd option).
     Before using this option, make sure that your files have been indeed
     decrypted correctly!

   - By skipping this time the ``-v`` option (verbose logging) you avoid listing
     every file being visited - only failures and totals are reported.

   - Use ``--overwrite`` or the more "selective" ``--fix`` option to
     re-generate all cleartext files or just those that had previously failed to
     decrypt, respectively.  They both accept an optional *file-extension*
     to construct the backup filename.
     Note that by default ``--overwrite`` does not make backups, while the
     ``-fix`` option, does.

   - If you are going to decrypt 1000s of file (i.e ``D:\\``), it's worth
     using the ``--precount`` option; it will consume some initial time to
     pre-calculate directories to be visited, and then a progress-indicator
     will be printed while decrypting.

   - Finally, You can "dry-run" all of the above (decrypting, deletion and backup)
     with the ``-n`` option.

   - Read decriptions for available options with::

        python teslacrack.py --help


And now, for some controversy...
================================

.. image:: https://cloud.githubusercontent.com/assets/16308406/11841119/45709ea2-a3fb-11e5-9df6-8dcc43a6812e.png
.. image:: https://cloud.githubusercontent.com/assets/16308406/11841120/4574e138-a3fb-11e5-981b-5b30e7f8bd84.png

The same day this happened, Kaspersky released this article: https://blog.kaspersky.com/teslacrypt-strikes-again/10860/

|flattr-donate| |btc-donate|


.. |flattr-donate| image:: https://img.shields.io/badge/flattr-donate-yellow.svg
    :alt: Donate to this project using Flattr
    :target: https://flattr.com/profile/Googulator
    :class: badge-flattr
.. |btc-donate| image:: https://img.shields.io/badge/bitcoin-donate-yellow.svg
    :alt: Donate once-off to this project using Bitcoin
    :target: https://blockchain.info/address/1AdcYneBgky3yMP7d2snQ5wznbWKzULezj
    :class: badge-bitcoin
.. |pypi-ver| image:: https://img.shields.io/badge/python-2.7%2B%2C%203.4%2B-blue.svg
