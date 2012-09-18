#!/usr/bin/env python
"""
Connect to ADE server, call OfferShell command, and wait to handle
SSH shell session requests from the server.
"""

from twisted.internet import reactor
from twisted.python.filepath import FilePath
from twisted.python import usage
from twisted.python import log

from ade import slave 


class Options(usage.Options):
    optParameters = [
        ['server', 's', 'localhost',
            "AmpDateEcho server to connect to."],

        ['ssh-port', None, 4422,
            "The port number for the AmpDateEcho service to connect to.",
            usage.portCoerce],

        ['ssh-key', None, "client_id_rsa",
            "Client private key to authenticate to the server with."],

        ['ssh-knownhosts', None, FilePath("known_hosts"),
            "SSH known_hosts file used to verify the Server's SSH key. "
            "Connections will not be allowed unless the Server's public key "
            "is listed in the known_hosts file.",
            FilePath],

        ['shell-user', None, 'teratorn',
            'The user account to run remote-support SSH shells as.'],
    ]

    def postOptions(self):
        fp = self['ssh-knownhosts']
        if not fp.exists():
            raise usage.UsageError('Path does not exist: %s' % (fp.path,))


def run():
    # parse command-line options.
    opts = Options()
    try:
        opts.parseOptions()
    except usage.UsageError, e:
        print e

    import sys; log.startLogging(sys.stdout)

    s = slave.ShellSlaveClientService(opts)
    s.startService()

    reactor.run()

if __name__ == '__main__':
    run()
