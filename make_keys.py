#!/usr/bin/env python
from twisted.conch.scripts import ckeygen
import os.path

def makeTestKeys():

    opts = ckeygen.GeneralOptions()
    opts['type'] = 'rsa'
    opts['bits'] = 1024
    opts['pass'] = '' # no passphrases - ugh. #

    for pth in ('client_id_rsa', 'server_id_rsa'):
        if not os.path.exists(pth):
            opts['filename'] = pth
            ckeygen.generateRSAkey(opts)

    if not os.path.exists('known_hosts'):
	text = " ".join( ["localhost"] + open("server_id_rsa.pub"
            ).readline().split()[:2] )
        with open('known_hosts', 'wb') as f:
            f.write(text)
            f.write('\n')

    if not os.path.exists('authorized_keys'):
        import shutil
        # add client pubkey to authorized_keys file
        shutil.copy('client_id_rsa.pub', 'authorized_keys')

if __name__ == '__main__':
    makeTestKeys()

