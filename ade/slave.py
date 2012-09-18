"""
Shellslave client
"""
from twisted.internet import protocol
from twisted.internet import defer

from twisted.application import internet

from twisted.conch.ssh import transport
from twisted.conch.ssh import connection
from twisted.conch.ssh import userauth
from twisted.conch.ssh import channel
from twisted.conch.ssh import session
from twisted.conch.ssh.common import NS, getNS
from twisted.conch.ssh.keys import Key

from twisted.conch import unix
from twisted.conch.client import knownhosts
from twisted.conch.interfaces import ISession

from twisted.python import log
from twisted.protocols import amp

import os
import os.path


from ade import server


class UserAuth(userauth.SSHUserAuthClient):
    def __init__(self, options, *args, **kw):
        userauth.SSHUserAuthClient.__init__(self, *args, **kw)
        self.options = options


    def getPublicKey(self):
        path = self.options['ssh-key']
        # this works with rsa too
        # just change the name here and in getPrivateKey
        if not os.path.exists(path) or self.lastPublicKey:
            # the file doesn't exist, or we've tried a public key
            return
        return Key.fromFile(filename=path+'.pub')


    def getPrivateKey(self):
        path = self.options['ssh-key']
        return defer.succeed(Key.fromFile(path))


class SSHClient(transport.SSHClientTransport):
    """
    Yes this is a Protocol, even though it inherits from
    a class named with the word "Transport" in it - go figure...
    """

    def connectionMade(self):
        transport.SSHClientTransport.connectionMade(self)


    def verifyHostKey(self, hostKey, fingerprint):
        log.msg('server host key fingerprint: %s' % (fingerprint,))
        hostname = self.factory.options['server']
        key = Key.fromString(hostKey)

        def _result(checkResult):
            if not checkResult:
                raise ValueError, "bad host key"
            return checkResult
        return defer.maybeDeferred(self.factory.knownhosts.hasHostKey,
                hostname, key).addCallback(_result)


    def connectionSecure(self):
        self.requestService(UserAuth(self.factory.options,
                                     self.factory.sshUsername,
                                     SSHConnection(self.factory.options,
                                                   self.factory)))

    # hacks to work around a silly Conch regression.
    # see issue #5999
    def getPeer(self):
        p = transport.SSHClientTransport.getPeer(self)
        return (p.address.host, p.address.port)

    def getHost(self):
        p = transport.SSHClientTransport.getHost(self)
        return (p.address.host, p.address.port)


class SSHConnection(connection.SSHConnection):
    def __init__(self, options, factory, *args, **kw):
        self.options = options
        self.factory = factory
        connection.SSHConnection.__init__(self, *args, **kw)

    def serviceStarted(self):
        """
        This service is started once we have connected and authentcated
        successfully to the SSH Server.
        """
        self.openChannel(ShellSlaveChannel(conn=self))

    def channel_session(self, windowSize, maxPacket, data):
        return ShellChannel(localWindow=windowSize, localMaxPacket=maxPacket,
                            remoteWindow=windowSize, remoteMaxPacket=maxPacket,
                            data=data, conn=self)



def logAndPassThrough(f):
    log.err(f)
    return f


ENV_WHITELIST = set(('LANG',))


class ShellChannel(session.SSHSession):
    """
    Channel that allows a shell to be opened as the UNIX user
    which was specifed on the command line (`shell-user'.)
    """
    name = 'session' # needed for commands
    session = None
    def __init__(self, conn=None, *args, **kw):
        self.environ = {}
        r = unix.UnixSSHRealm()
        avatar = r.requestAvatar(conn.options['shell-user'],
                                 None, unix.UnixConchUser)[1]
        session.SSHSession.__init__(self, *args, avatar=avatar, conn=conn, **kw)

    def channelOpen(self, ignoredData):
        self.avatar.conn = self.conn

    def request_env(self, data):
        """
        data should contain two netstrings.
        The first is an env var name, the second its requested value.
        """
        name, rest = getNS(data)
        value, rest = getNS(rest)
        if rest:
            raise ValueError("Bad data given in env request.")

        if name in ENV_WHITELIST:
            log.msg("env request: %s=%s" % (name, value))

            if not self.session:
                self.session = ISession(self.avatar)

            self.session.environ[name] = value
            return True
        else:
            log.msg("env request REJECTED: %s=%s" % (name, value))
            return False


class ShellSlaveChannel(channel.SSHChannel):
    """
    Channel, that when open, requests the AMP subsystem,
    and makes an AMP call.

    Upon successful subsystem open, we make a `OfferShell' AMP call
    to let the peer know, that we are ready to service shell requests.
    """
    name = 'session' # needed for commands

    def __init__(self, *args, **kw):
        channel.SSHChannel.__init__(self, *args, **kw)
        self.buf = ''
        self.client = None
        self.session = None

    def openFailed(self, reason):
        log.msg('failed to open channel', reason)
        self.conn.transport.transport.loseConnection()

    def channelOpen(self, ignoredData):
        d = self.conn.sendRequest(self, 'subsystem', NS('amp'), wantReply=True)
        d.addCallback(self._cbSubsystem)
        d.addErrback(logAndPassThrough)
        d.addErrback(lambda f: self.conn.transport.transport.loseConnection())

    def _cbSubsystem(self, result):
        self.client = amp.AMP()
        self.client.makeConnection(self)
        self.dataReceived = self.client.dataReceived

        self.client.callRemote(server.OfferShell
                ).addCallback(self._cbDone
                ).addErrback(self._ebFailed)

    def _cbDone(self, r):
        log.msg("AMP `OfferShell' call succeeded. Ready to service shell requests.")

    def _ebFailed(self, f):
        log.msg("AMP `OfferShell' call failed:")
        log.err(f)
        self.conn.transport.transport.loseConnection()


class ShellSlaveClientService(internet.TCPClient):
    def __init__(self, options):
        self.options = options

        # Try ReconnectingClientFactory to maintain a persistent connection.
        #f = protocol.ReconnectingClientFactory()
        f = protocol.ClientFactory()
        f.sshUsername = 'shellslave' # store here for convenience of the protocol
        f.protocol = SSHClient
        f.maxDelay = 60 * 5 # 5 minutes

        f.options = options
        f.knownhosts = knownhosts.KnownHostsFile.fromPath(
                options['ssh-knownhosts'])

        # Init TCPClient
        internet.TCPClient.__init__(self, options['server'],
                                    options['ssh-port'], f)

