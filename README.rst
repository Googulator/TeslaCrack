#################################################
TeslaCrack - decryptor for the TeslaCrypt malware
#################################################

This is a tool for decrypting files that were encrypted with the latest version
(variously known as "v8" or "v2.2.0") of the TeslaCrypt ransomware. This new version
can be recognized from the extension ".vvv" added to the names of encrypted files, and the
file names of the ransom notes being ``Howto_RESTORE_FILES.txt``.
The tool should also work against other recent versions of TeslaCrypt - for ancient versions,
use tesladecrypt or TeslaDecoder together with the Bitcoin-based key reconstructor instead.

*TeslaCrack* implements an integer factorization attack against TeslaCrypt's encryption
scheme. The actual factorization is not implemented within *TeslaCrack*, instead,
it will provide the numbers to be factored, which you will need to input into an existing
factoring tool such as [YAFU or msieve](https://www.google.com/search?q=msieve+factorization).

Two files are included:

- ``teslacrack.py``: parses ``.vvv`` file headers, extracts their encrypted-AES-keys,
  and if their corresponding session-key has already been reconstructed earlier
  (by following the steps described below), it decrypts those files.
- ``unfactor.py``: reconstructs the session-key from the previously found factors
  of the encrypted-AES-key.

This utility requires a working Python environment (2.7.x or 3.4.x recommended,
tested with 2.7.11 & WinPython-3.4.3), with pycryptodome installed.



Install Python
==============

If you don't yet have a working Python environment, do the following:

1. Download the latest Python 2.7 or Python-3 64-bit releases.  There are
   at least 2 choices (with [Anaconda ](https://www.continuum.io/downloads)
   being the 3rd):

   - Try the "official" distributions from https://www.python.org, which requires
     admin-rights to install it and to add the necessary packages.or
     Python.org by default offers you a 32-bit version! Make sure
     to explicitly **choose the 64-bit version** if it is suported by your OS.
     Make sure to select the option to add Python to your ``PATH``.
   - Try the portable [WinPython 3.4 "slim"](http://sourceforge.net/projects/winpython/files/WinPython_3.4/3.4.3.7/)
     distribution.  By default it does not modify your ``PATH`` so you
     **must run the included command-propmpt executable**.
     Anf although  **it does not require admin-rights to install**,
     eventually you may need admin-rights if your files come from a different user.
   - A 32-bit Python can also be used, but it will be significantly slower,
     and requires a different versiom of *pycryptodome* lib.

2. At a command-prompt with python enabled (and with administrative rights, if in "official" python),
   execute the following commands::

       REM The cmd below is required only for the "official" python-2
       python -c "import urllib2; print urllib2.urlopen('https://bootstrap.pypa.io/ez_setup.py').read()" | python

       easy_install pip
       pip install pycryptodome
       pip install ecdsa                REM optional, needed only for unfactor_ecdsa.py
       pip install pybitcoin            REM optional, needed only for unfactor_bitcoin.py

In addition, you need a program for factoring large numbers.
For this purpose, I recommend using Msieve and the factmsieve.py wrapper.
Run the factorization on a fast computer, as it can take a lot of processing power.
On a modern dual-core machine, most encrypted AES-session-keys can be factorized
in a few hours, with some unlucky keys possibly taking up to a week.


How to decrypt your ``.vvv`` files
================================

1. Collect an encrypted file from the attacked machine in your *working folder*.
   Choose a file with a known initial magic number - ``unfactor.py`` is pre-configured
   for working with PDF files; change the magic number in ``unfactor.py`` from '%PDF'
   to the correct value if you did not selected a PDF:

   - ``PK`` for .zip;
   - ``ODF`` for .docx/OOXML files;
   - ``\xff\xd8`` for JPEGs;
   - ``\xd0\xcf\x11\xe0`` for MS Office .doc files

   (in *python-3* bytes are given like that: ``b'\x3a'``).

2. Put the seleted file into the same folder as ``unfactor.py`` and ``teslacrack.py``
   (your working folder).

3. If the extension of your encrypted files is not ``.vvv``, edit ``teslacrack.py``
   to append  into ``tesla_extensions`` string-list.

4. Then enter this command in your working folder to process your encrypted file
   (notice the ``.`` at the end, or you may use the name of your encrypted file)::

       python teslacrack.py .

   It will print out two hex numbers.  **The first number is encrypted-AES-key**.

   - If you get an error message, make sure that you have Python and *pycrypto* installed.
     See instructions above.

5. Convert your number from hex to decimal, e.g. in python type ``int('ae1b015a', 16)``,
   and search [factordb.com](http://factordb.com/) for your number. If you are lucky,
   it may have been already factored, and you can skip the next step.

6. Factor the AES key printed by ``teslacrack.py`` above:

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

7. To reconstruct the AES-session-key that has encrypted your files, run::

       python unfactor.py  <encrypted file>  <primes from previous step, separated by spaces>

   It will print out any session-key candidates found (usually just one).

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

8. Edit ``teslacrack.py``, and add your encrypted and reconstructed AES session
   key-pair(s) into the ``known_keys`` array.

9. Repeat step 4. The decrypted file should appear next to the encrypted ``.vvv`` file;
   verify that it was decrypted correctly. If not, redo steps 7-8 with
   the other candidate AES-session-keys from ``unfactor.py``.

10. To decrypt all of your files run from an administrator command prompt::

        python teslacrack.py C:\\

    - Some machines may show multiple AES-session-keys (i.e. if you had rebooted while
      infection was running); ``teslacrack.py`` will warn you for this, and
      it will print in the end any encrypted AES-key(s) it has encountered.
      If this happens, repeat all steps for the newly found key(s).
    - ``teslacrack.py`` takes an optional ``--delete`` parameter, which will delete
      the encrypted copies of any file it successfully decrypts.
      Before using this option, make sure that your files are  indeed decrypted
      correctly!
    - And extra ``-v`` option enables verbose logging, listing every file being visited.
      Oherwise, only failures will be reported.


And now, for some controversy...
![](https://cloud.githubusercontent.com/assets/16308406/11841119/45709ea2-a3fb-11e5-9df6-8dcc43a6812e.png)
![](https://cloud.githubusercontent.com/assets/16308406/11841120/4574e138-a3fb-11e5-981b-5b30e7f8bd84.png)

The same day this happened, Kaspersky released this article: https://blog.kaspersky.com/teslacrypt-strikes-again/10860/

<span class="badge-flattr"><a href="https://flattr.com/profile/Googulator" title="Donate to this project using Flattr"><img src="https://img.shields.io/badge/flattr-donate-yellow.svg" alt="Flattr donate button" /></a></span>
<span class="badge-bitcoin"><a href="bitcoin:1AdcYneBgky3yMP7d2snQ5wznbWKzULezj" title="Donate once-off to this project using Bitcoin"><img src="https://img.shields.io/badge/bitcoin-donate-yellow.svg" alt="Bitcoin donate button" /></a></span>
