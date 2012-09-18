#!/usr/bin/env python
"""
Call `Echo' Command on an ADE server.
"""

from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.conch.client import knownhosts

from twisted.python.filepath import FilePath
from twisted.python import usage
from twisted.python import log
from twisted.protocols import amp

import os
import sys

from ade.server import Echo
from ade import ampclient


class Exit:
    code = 0 # process exit code


class AMPEchoClient(amp.AMP):
    @inlineCallbacks
    def connectionMade(self):
        try:
            print 'Calling Echo command...'
            r = yield self.callRemote(Echo, msg=" ".join(sys.argv[2:]))
            print "Echoed: %s" % (r['echo'],)
            Exit.code = 0
        except Exception, e:
            print "Failed to echo:", e
            Exit.code = 1
        finally:
            reactor.stop()


class AMPSSHClient(ampclient.SSHClient):
    ampProtocol = AMPEchoClient


class Options(usage.Options):
    """
    Call `Echo' command on an "AmpDateEcho" server.
    """
    optParameters = [
        ['ssh-port', None, 4422,
            "Port number for the SSH/AMP service to connect to.",
            usage.portCoerce],

        ['ssh-key', None, "./client_id_rsa",
            "Client private key to authenticate to the server with."],

        ['ssh-knownhosts', None, FilePath("./known_hosts"),
            "SSH known_hosts file used to verify the Server's SSH key. "
            "Connections will not be allowed unless the Server's public key "
            "is listed in the known_hosts file.",
            FilePath],
    ]

    def parseArgs(self, *args):
        if len(args) < 2:
            raise usage.UsageError('Specify [user@]host, and some arguments to echo.')

        userHost = args[0]
        if '@' not in userHost:
            username = os.getlogin()
            host = userHost
        else:
            username, host = userHost.split('@')

        self['username'] = username
        self['server'] = host


    def postOptions(self):
        fp = self['ssh-knownhosts']
        if not fp.exists():
            raise usage.UsageError('Path does not exist: %s' % (fp.path,))


class ClientFactory(protocol.ClientFactory):
    def clientConnectionFailed(self, connector, reason):
        print 'Connection failed: %s' % (reason.value,)
        Exit.code = 1
        reactor.stop()


def run():
    # parse command-line options.
    opts = Options()
    try:
        opts.parseOptions()
    except usage.UsageError, e:
        print e
        sys.exit(1)

    # Do want a quiet client - so no normal twisted logging.
    #   (enable this for debugging.)
    #log.startLogging(sys.stdout)

    f = ClientFactory()
    f.sshUsername = opts['username'] # store here for convenience of the protocol
    f.protocol = AMPSSHClient
    f.maxDelay = 60 * 5 # 5 minutes

    f.options = opts
    f.knownhosts = knownhosts.KnownHostsFile.fromPath(
            opts['ssh-knownhosts'])

    # Init TCPClient
    reactor.connectTCP(opts['server'], opts['ssh-port'], f)

    reactor.run()


if __name__ == '__main__':
    run()
    sys.exit(Exit.code)

