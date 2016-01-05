# TeslaCrack
Decryptor for the TeslaCrypt malware

This is a tool for decrypting files that were encrypted with the latest version
(variously known as "v8" or "v2.2.0") of the TeslaCrypt ransomware. This new version
can be recognized from the extension ".vvv" added to the names of encrypted files, and the
file names of the ransom notes being "Howto_RESTORE_FILES.txt".
The tool should also work against other recent versions of TeslaCrypt - for ancient versions,
use tesladecrypt or TeslaDecoder together with the Bitcoin-based key reconstructor instead.

TeslaCrack implements an integer factorization attack against TeslaCrypt's encryption
scheme. The actual factorization is not implemented within TeslaCrack, instead,
it will provide the numbers to be factored, which you will need to input into an existing
factoring tool such as YAFU or msieve.

Two files are included:
- teslacrack.py parses .vvv file headers, identifies their public keys, and for files where
  the corresponding private key is already known, performs the actual decryption.
- unfactor.py reconstructs the private key from the previously found factors of the public key.

This utility requires a working Python environment (2.7.x recommended, tested with 2.7.11),
with pycrypto installed. If you don't yet have a working Python environment, do the following:

1. Download the latest Python 2.7 64-bit release from https://www.python.org
   * Make sure to select the option to add Python to your PATH.
   * A 32-bit Python can also be used, but will be significantly slower, and requires a different versiom of pycrypto
.
     If possible, use a 64-bit system for decrypting your files.
     Python.org by default offers you a 32-bit version! Make sure
     to explicitly choose the 64-bit version.
2. At a command prompt with administrative rights, execute the following commands:<br />
   <code>python -c "import urllib2; print urllib2.urlopen('https://bootstrap.pypa.io/ez_setup.py').read()" | python</code><br />
   <code>easy_install pip</code><br />
   <code>pip install http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1-cp27-none-win_amd64.whl</code><br />
   <code>pip install ecdsa</code> (optional, needed only for unfactor_ecdsa.py)<br />
   <code>pip install coinkit</code> (optional, needed only for unfactor_bitcoin.py)

In addition, you need a program for factoring large numbers.
For this purpose, I recommend using Msieve and the factmsieve.py wrapper.
Run the factorization on a fast computer, as it can take a lot of processing power.
On a modern dual-core machine, most TeslaCrypt keys can be factorized in a few hours, with some
unlucky keys possibly taking up to a week.

## How to decrypt your vvv files after a TeslaCrypt infection

Note: Commands written <code>like this</code> need to be executed from the command line.

1. Collect an encrypted file from the attacked machine.
   Choose a file with a known initial magic number - unfactor.py is pre-configured
   for working with PDF files; change the magic number in unfactor.py from '%PDF' to the correct
   value if you are not using a PDF (e.g. 'PK' for .zip, ODF or .docx/OOXML files; '\xff\xd8' for
   JPEGs; or '\xd0\xcf\x11\xe0' for MS Office .doc files).
2. Put the collected file into the same folder as unfactor.py and teslacrack.py (the working folder)
3. If the extension of your encrypted files is not '.vvv', edit teslacrack.py to match.
4. Run <code>python teslacrack.py .</code> in the working folder. It will print out two hex numbers.
   Te first hex number is your AES public key.
   * If you get an error message, make sure that you have Python and pycrypto installed.
     See above for instructions.
5. Convert your number from hex to decimal and search [factordb.com](http://factordb.com/) for your number. If you are lucky, it has already been factored and you can skip the next step. 
6. Factor the AES key printed by teslacrack.py  
   * E.g. using msieve: run <code>msieve -v -e 0x\<public key from teslacrack.py\></code>
     The -e switch is needed to do a "deep" elliptic curve search, which speeds up msieve for numbers
     with many factors (by default, msieve is optimized for semiprimes such as RSA moduli)
   * Alternatively, you can use YAFU, which is multithreaded, but tends to crash often for me
     If you use YAFU, make sure to run it from command line using the <code>-threads</code> option!
   * For numbers with few factors (where -e is ineffective, and msieve/YAFU runs slow),
     use factmsieve.py, which is more complicated, but also faster, multithreaded, and doesn't tend
     to crash
7. Run <code>python unfactor.py \<name of encrypted file\> \<primes from previous step, separated by spaces\></code>
   to reconstruct the AES private key. It will print out any private key candidates found
   (usually just one).
   * Sometimes, unfactor.py will print the same candidate multiple times. This is a known bug,
     please disregard it.
   * Alternatively, you can use unfactor_ecdsa.py to get your keys - this is slower, and requires the
     "ecdsa" Python module to be installed; however, unlike unfactor.py, it can also reconstruct
     Bitcoin private keys (to be used with TeslaDecoder), not just AES ones. Also, unfactor_ecdsa.py
     is guaranteed to always yield only correct keys, and can recover keys even from files without
     known magic numbers, while unfactor.py is filetype-dependent, and may sometimes
     report false positive keys. Syntax for the two scripts is the same, simply add <code>_ecdsa</code>
     to the name of the script.
   * For very old TeslaCrypt infections, a third key reconstructor is provided, which uses the Bitcoin
     ransom address instead of a sample file. Both the Bitcoin address and the public key can be obtained
     from the recovery file in the affected machine's Documents folder for such old infections.
     The Bitcoin address is the first line of the file, while the public key (which needs to be factored)
     is the third line. Syntax is like unfactor.py, but use the Bitcoin address in place of a filename.
     Note that teslacrack.py can't decode the file format used by old TeslaCrypt, so you will need
     to perform the actual decryption using TeslaDecoder.
8. Edit teslacrack.py, and add your public and private AES keys to the known_keys array.
9. Repeat step 3. The decrypted file should appear next to the encrypted vvv file - verify that it was decrypted correctly.
   If not, redo steps 7-8 with the other candidate keys from unfactor.py
10. Run <code>python teslacrack.py C:\\</code> from an administrator command prompt to decrypt your files.
   * Some machines show multiple session keys - teslacrack.py will warn you of this, and print any
     unknown session keys it encounters. If this happens, repeat all steps with the newly found key.
   * teslacrack.py takes an optional <code>--delete</code> parameter, which will delete the encrypted copies of
     any file it successfully decrypts. Before using this option, always verify that teslacrack.py
     is indeed decrypting correctly!

And now, for some controversy...
![](https://cloud.githubusercontent.com/assets/16308406/11841119/45709ea2-a3fb-11e5-9df6-8dcc43a6812e.png)
![](https://cloud.githubusercontent.com/assets/16308406/11841120/4574e138-a3fb-11e5-981b-5b30e7f8bd84.png)

The same day this happened, Kaspersky released this article: https://blog.kaspersky.com/teslacrypt-strikes-again/10860/ 

<span class="badge-flattr"><a href="https://flattr.com/profile/Googulator" title="Donate to this project using Flattr"><img src="https://img.shields.io/badge/flattr-donate-yellow.svg" alt="Flattr donate button" /></a></span>
<span class="badge-bitcoin"><a href="bitcoin:1AdcYneBgky3yMP7d2snQ5wznbWKzULezj" title="Donate once-off to this project using Bitcoin"><img src="https://img.shields.io/badge/bitcoin-donate-yellow.svg" alt="Bitcoin donate button" /></a></span>
