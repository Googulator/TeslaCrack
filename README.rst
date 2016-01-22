#####################################################
TeslaCrack - decryptor for the TeslaCrypt ransomeware
#####################################################

This is a tool for decrypting files that were encrypted with the latest version
(variously known as "v8" or "v2.2.0") of the **TeslaCrypt ransomware**.
This new version can be recognized from the extension ``.vvv`` or ``.ccc`` added
to the names of encrypted files, and/or the filenames of the ransom notes being
``Howto_RESTORE_FILES.txt``.

The tool should also work against other recent versions of TeslaCrypt - for ancient versions,
use *tesladecrypt* or *TeslaDecoder* together with the Bitcoin-based key
reconstructor instead (``unfactor_bitcoin.py``).

Overview
--------
We recapitulate `how TeslaCrypt ransomware works and explain the weakness
<http://www.bleepingcomputer.com/news/security/teslacrypt-decrypted-flaw-in-teslacrypt-allows-victims-to-recover-their-files/>`_
that is relevant for this cracking tool:

1. *TeslaCrypt* creates a symmetrical AES-session-key that will be used to encrypt your files,
2. it then asymmetrically ECDH-encrypts that AES-key and transmits the private-ECDH-key
   to the operators of the ransomware (but that is irrelevant here), and finally
3. it starts encrypting your files one-by-one, attaching the encrypted-AES-key
   into their header.

- Multiple AES-keys are generated if you interrupt the ransomware while it encrypts
  your files (i.e. reboot).

*TeslaCrack* implements an integer factorization attack against TeslaCrypt's asymmetric encryption
scheme. The actual factorization is not implemented within *TeslaCrack*, instead,
it extracts the numbers to be factored, which you will need to feed them into existing
factoring tool, such as `YAFU or msieve <https://www.google.com/search?q=msieve+factorization>`_.

Two files are included:

- ``teslacrack.py``: parses the headers from ``.vvv`` (or ``.ccc``) files,
  extracts their encrypted-AES-keys, and if their corresponding session-key
  has already been reconstructed earlier (by following the steps described below),
  it decrypts those files.
- ``unfactor.py``: reconstructs the session-key from the factorized(externally)
  encrypted-AES-keys.


Installation
============

You need a working Python 2.7 or Python-3.4+ environment,
**preferably 64-bit** (if supported by your OS).
A 32-bit Python can also work, but it will be significantly slower,
and will require a different version of *pycryptodome* lib.

Install Python
--------------
In *Windows*, the following 2 alternatives have been tested:

- The `"official" distributions <https://www.python.org>`_, which **require
  admin-rights to install and to ``pip``-install the necessary packages.**
  Note the official site by default may offer you a 32-bit version -
  choose explicitly the 64-bit version.
  Check also the option for adding Python into your ``PATH``.

- The portable `WinPython 3.4 "slim" <http://sourceforge.net/projects/winpython/files/WinPython_3.4/3.4.3.7/>`_
  distribution.  By default it does not modify your ``PATH`` so you
  **must run all commands from the included command-propmpt executable**.
  And although  it **does not require admin-rights to install**,
  you may eventually need admin-rights if the files to decrypt originate
  from a different user.

Install TeslaCrypt
------------------
1. At a command-prompt with python enabled (and with admin-rights in the "official" distribution),
   execute the following commands::

       pip install pycryptodome
       pip install ecdsa                REM optional, needed only for unfactor_ecdsa.py
       pip install pybitcoin            REM optional, needed only for unfactor_bitcoin.py

   - If you get an error like ``'pip' is not recognized as an internal or external command ...``
     then you may execute the following Python-2 code and re-run the commands above::

         python -c "import urllib2; print urllib2.urlopen('https://bootstrap.pypa.io/ez_setup.py').read()" | python
         easy_install pip


2. In addition, you need a program for factoring large numbers.

   For this purpose, I recommend using Msieve (e.g. http://sourceforge.net/projects/msieve/)
   and the ``factmsieve.py`` wrapper.
   Run the factorization on a fast computer, as it can take a lot of processing power.
   On a modern dual-core machine, most encrypted AES-keys can be factorized
   in a few hours, with some unlucky keys possibly taking up to a week.


How to decrypt your ``.vvv`` files
==================================

1. Collect an encrypted file from the attacked machine in your *working folder*.
   Choose a file with a known initial magic number - ``unfactor.py`` is pre-configured
   for working with PDF files; change the magic number in ``unfactor.py`` from '%PDF'
   to the correct value if you did not selected a PDF:

   - ``PK`` --> .zip;
   - ``ODF`` --> .docx/OOXML files;
   - ``\xff\xd8`` --> JPEGs;
   - ``\xd0\xcf\x11\xe0`` --> MS Office .doc files

   (in *python-3* bytes are given like that: ``b'\x3a'``).

   Note that commands below assume that your *working folder* is the one
   containing ``unfactor.py`` and ``teslacrack.py`` files.

2. If the extension of your encrypted files is not ``.vvv`` or ``.ccc``,
   edit ``teslacrack.py`` to append it into ``tesla_extensions`` string-list.

3. Enter this command in your working folder to process your encrypted file
   (notice the ``.`` at the end,; you may use the name of your encrypted file instead)::

       python -v teslacrack.py .

   It will print out two hex numbers.  **The first number is your encrypted-AES-key**.

   - If you get an error message, make sure that you have Python and *pycryptodome* installed
     (see instructions above).

4. Convert your hexadecimal AES-key to decimal, e.g. in python type ``int('ae1b015a', 16)``,
   and search `factordb.com <http://factordb.com/>`_ for this number. If you are lucky,
   it may have been already factored, and you can skip the next step :-)

5. Factor the AES key printed by ``teslacrack.py`` above:

   - Using *msieve*::

         msieve -v -e 0x\<encrypted-AES key from teslacrack.py>

     The ``-e`` switch is needed to do a "deep" elliptic curve search,
     which speeds up *msieve* for numbers with many factors (by default,
     *msieve* is optimized for semiprimes such as moduli)

   - Alternatively, you can use *YAFU*, which is multithreaded, but
     tends to crash often (at least for me)
     If you use *YAFU*, make sure to run it from command line using
     the ``-threads`` option!

   - For numbers with few factors (where ``-e`` is ineffective, and *msieve/YAFU*
     run slow), use ``factmsieve.py`` (downloaded optionally above), which is
     more complicated, but also faster, multithreaded, and doesn't tend to crash.

6. To reconstruct the AES-key that has encrypted your files, run::

       python unfactor.py  <encrypted file>  <primes from previous step, separated by spaces>

   It will reconstruct and print any decrypted AES-keys candidates (usually just one).

   - Sometimes, ``unfactor.py`` will print the same candidate multiple times.
     This is a known bug, please disregard it.

   - Alternatively, you can use ``unfactor_ecdsa.py`` to get your keys - this is slower,
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

7. Edit ``teslacrack.py``, and add a new key-pair into the ``known_keys`` array
   like that::

      <encrypted-AES-key>: <1st decrypted-AES-key candidate>,

8. Repeat step 3. A decrypted file should now appear next to the encrypted
   ``.vvv`` or `.ccc`` file; verify that it has been decrypted correctly.

   - If not, redo step 7, replacing every time a new candidate decrypted AES-key
     in the pair.

10. To decrypt all of your files run from an administrator command prompt::

        python teslacrack.py D:\\

    - In some cases you may start receiving error-messages, saying ``"Cannot decrypt 'file/path', unknown key!"``.
      That means that some of your files have been encrypted with different AES-keys
      (i.e. you had interrupted the infection with a reboot?).
      ``teslacrack.py`` will print at the end all new encrypted AES-key(s) -
      repeat procedure from step 4 for all newly discovered key(s) :-(

    - ``teslacrack.py`` accepts an optional ``--delete`` parameter, which will delete
      the encrypted copies of any file it successfully decrypts.
      Before using this option, make sure that your files are  indeed decrypted
      correctly!

    - By skipping this time the ``-v`` option (verbose logging) you avoid listing
      every file being visited - only failures and totals are reported.


And now, for some controversy...

.. image:: https://cloud.githubusercontent.com/assets/16308406/11841119/45709ea2-a3fb-11e5-9df6-8dcc43a6812e.png
.. image:: https://cloud.githubusercontent.com/assets/16308406/11841120/4574e138-a3fb-11e5-981b-5b30e7f8bd84.png

The same day this happened, Kaspersky released this article: https://blog.kaspersky.com/teslacrypt-strikes-again/10860/

.. image:: https://img.shields.io/badge/flattr-donate-yellow.svg
    :alt: Donate to this project using Flattr
    :target: https://flattr.com/profile/Googulator
    :class: badge-flattr
.. image:: https://img.shields.io/badge/bitcoin-donate-yellow.svg
    :alt: Donate once-off to this project using Bitcoin
    :target: bitcoin:1AdcYneBgky3yMP7d2snQ5wznbWKzULezj
    :class: badge-bitcoin
