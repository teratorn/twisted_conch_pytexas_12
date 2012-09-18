#!/usr/bin/env python
"""
AmpDateEcho date fetching client.

With a manhole service too, for fun
"""

from twisted.internet import reactor
from twisted.application import internet
from twisted.conch.insults import insults
from twisted.conch.manhole import ColoredManhole
from twisted.conch.manhole_ssh import ConchFactory
from twisted.conch.manhole_ssh import TerminalRealm
from twisted.cred import portal

from twisted.python import usage
from twisted.python import log

import os
import sys

from ade.server import AMPSSHService


class Options(usage.Options):
    optParameters = [

        # SSH Server
        ['ssh-port', None, 4422,
            "Port number for the SSH/AMP service to listen on.",
            usage.portCoerce],

        # Server private keypair.
        ['host-key', None, "server_id_rsa",
            "SSH server host key. (public key expected at same path with .pub extension.)"],

        # authorized_keys database.
        ['authorized-keys', None, "./authorized_keys",
            "Keys to accept for pubkey authentication."],


        # Manhole - natively uses Conch to provide python shell service.
        ['manhole-port', None, 5555,
            "Manhole port to listen on (SSH Manhole)."],
        # Should use Endpoints, here.
        ['manhole-if', None, '127.0.0.1',
            "Interface for Manhole to listen on."],
    ]

    def postOptions(self):
        if not os.path.exists(self['authorized-keys']):
            raise usage.UsageError("authorized-keys file does not exist: %s" % (self['authorized-keys'],))


def makeManholeService(ns, options):
    from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
    checker = InMemoryUsernamePasswordDatabaseDontUse(admin="admin") 

    def chainProtocolFactory():
        return insults.ServerProtocol(ColoredManhole, namespace=ns)

    rlm = TerminalRealm()
    rlm.chainedProtocolFactory = chainProtocolFactory
    ptl = portal.Portal(rlm, [checker])
    f = ConchFactory(ptl)
    return internet.TCPServer(options['manhole-port'], f)


def run():
    # parse command-line options.
    opts = Options()
    try:
        opts.parseOptions()
    except usage.UsageError, e:
        print e
        sys.exit(1)

    log.startLogging(sys.stdout)

    s = AMPSSHService(opts)
    s.startService()

    ns = {'ssh' : s}
    manhole = makeManholeService(ns, opts)
    ns['manhole'] = manhole
    manhole.startService()


    reactor.run()

if __name__ == '__main__':
    run()
