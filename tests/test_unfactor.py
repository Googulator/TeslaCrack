from collections import OrderedDict
import textwrap
import unittest

import ddt
import yaml

import unfactor


app_db_txt = r"""
keys:
    - name     : ankostis
      type     : AES
      encrypted: 7097DDB2E5DD08950D18C263A41FF5700E7F2A01874B20F402680752268E43F4C5B7B26AF2642AE37BD64AB65B6426711A9DC44EA47FC220814E88009C90EA
      decrypted: \x01\x7b\x16\x47\xd4\x24\x2b\xc6\x7c\xe8\xa6\xaa\xec\x4d\x8b\x49\x3f\x35\x51\x9b\xd8\x27\x75\x62\x3d\x86\x18\x21\x67\x14\x8d\xd9
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
      decrypted: \x1b\x5c\x52\xaa\xfc\xff\xda\x2e\x71\x00\x1c\xf1\x88\x0f\xe4\x5c\xb9\x3d\xea\x4c\x71\x32\x8d\xf5\x95\xcb\x5e\xb8\x82\xa3\x97\x9f'
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
"""

# def config_yaml():
#     """From http://stackoverflow.com/a/21048064/548792"""
#     yaml.add_representer(OrderedDict, lambda dumper, data:
#             dumper.represent_dict(data.items()))
#     yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
#             lambda loader, node: OrderedDict(loader.construct_pairs(node)))
# config_yaml()

def read_app_db():
    return yaml.load(textwrap.dedent(app_db_txt))

app_db = read_app_db()


@ddt.ddt
class TUnfactor(unittest.TestCase):

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'AES'])
    def test_undecrypt_AES_keys(self, key_rec):
        for f in key_rec.get('crypted_files', ()):
            factors = [int(fc) for fc in key_rec['factors']]
            exp_aes_key = key_rec['decrypted']
            aes_key = unfactor.undecrypt(f, factors)
            #print(key_rec['name'], f, aes_key, exp_aes_key)
            self.assertIn(exp_aes_key, aes_key,
                    (key_rec['name'], f, aes_key, exp_aes_key))

