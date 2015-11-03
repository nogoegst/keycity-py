#!/usr/bin/python3

import hashlib
import keycity
import binascii

if __name__ == "__main__":
    keycity = keycity.Keycity()
        #print(binascii.hexlify(key.fp.sha1).decode('utf-8'))
    #    print(key.fp.onion_address)

    keycity.list_available_onions()

    digest = hashlib.sha1("msga".encode('utf-8')).digest()
    sig = keycity.sign_please(digest, 'eu')
    pk = keycity.pubkey_please('eu')
    print(pk)
    print(binascii.hexlify(sig).decode('utf-8'))
