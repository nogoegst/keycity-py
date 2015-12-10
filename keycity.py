from pyblake2 import blake2s
import hashlib
import Crypto.PublicKey.RSA
import Crypto.Util.number
import base64
import binascii
import math
import yaml
import util
import OpenPGPyCard



class Fingerprint:
    def __init__(self, key):
        self.blake2s = self.calc_blake2s_digest(key)
        self.sha1 = self.calc_sha1_digest(key)
        self.onion_permid = self.calc_onion_permid(key)
        self.onion_address = self.calc_onion_address(key)

    def calc_blake2s_digest(self, key):
        return blake2s(key.asn1).digest()

    def calc_sha1_digest(self, key):
        return hashlib.sha1(key.asn1).digest()
   
    def calc_onion_permid(self, key):
        return self.calc_sha1_digest(key)[:10]
    
    def calc_onion_address(self, key):
        return base64.b32encode(self.calc_onion_permid(key)).decode().lower()
    
    def matches(self, keyid):
        for fp in [self.blake2s, self.sha1, self.onion_address]:
            try:
                if keyid in fp:
                    return True
            except:
                pass
            try:
                binkeyid = binascii.unhexlify(keyid.encode('utf-8'))
                if binkeyid in fp:
                    return True
            except:
                pass
        return False
            

class Key:
    def __init__(self, address):
        self.street, self.house = address
        if self.street == 'keyfile':
            self.key = util.key_decrypt_prompt(self.house)
        if self.street == 'openpgpcard':
            self.key = self._get_pubkey_openpgpcard()
        if self.key is None:
            self.key = Crypto.PublicKey.RSA.generate(1024)
        
        self.asn1 = self._get_asn1_sequence() 
        self.fp = Fingerprint(self)
        return

    def _get_asn1_sequence(self):
        seq = Crypto.Util.asn1.DerSequence()
        seq.append(self.key.n)
        seq.append(self.key.e)
        asn1_seq = seq.encode()
        return asn1_seq
            
    def _sign_digest_keyfile(self, digest):
        if self.key.has_private():
            digest = util.add_pkcs1_padding(digest)
            (signature_long, ) = self.key.sign(digest, None)
            signature_bytes = Crypto.Util.number.long_to_bytes(signature_long, math.ceil(self.key.size()/8))   
            return signature_bytes
        else:
            return None

    def _get_pubkey_openpgpcard(self):
        card = OpenPGPyCard.Card(transmitter="pcscd")
        pubkey = card.get_pubkey(self.house)
        #card.disconnect() # Breaks everything somehow
        return pubkey

    def _sign_digest_openpgpcard(self, digest):
        card = OpenPGPyCard.Card()
        card.verify_pin2(batch=True) # TODO: make pin available in map
        signature_bytes = card.sign_digest(digest, self.house)
        #card.disconnect()
        return signature_bytes

    def sign(self, digest):
        if self.street == "keyfile":
            return self._sign_digest_keyfile(digest)
        if self.street == "openpgpcard":
            return self._sign_digest_openpgpcard(digest)


class Keycity:
    def __init__(self, config_file="keycitymap.yaml"):
        with open(config_file, 'r') as f:
            self.map = yaml.safe_load(f.read())

    def lookup_all(self, keyid=''):
        found = []
        for street in self.map:
            for house in self.map[street]:
                try:
                    address = (street, house)
                    key = Key(address)
                    if key.fp.matches(keyid):
                        found.append(key)
                except:
                    pass
        return found

    def lookup(self, keyid):
        found = self.lookup_all(keyid)
        if len(found) > 1:
            print("[w] Multiple keys found. Returning first found key.")
            return found[0]
        if len(found) == 0:
            print("[w] Key not found")
            return None
        if len(found) == 1:
            #print("onion: " + found[0].fp.onion_address)
            #print("on street: " + found[0].street)
            return found[0] 

    def sign_please(self, digest, keyid):
        return self.lookup(keyid).sign(digest)
    
    def pubkey_please(self,keyid):
        return self.lookup(keyid).key

    def list_available_onions(self):
        for key in self.lookup_all():
            print(key.fp.onion_address)
