"""
An SSH client that requests the "amp" subsystem, and connects the user-supplied
AMP protocol to it.
"""
from twisted.conch.ssh import transport
from twisted.conch.ssh import userauth
from twisted.conch.ssh import connection
from twisted.conch.ssh import channel
from twisted.conch.ssh.common import NS
from twisted.python import log
from twisted.conch.ssh.keys import Key
from twisted.internet import defer

import os


class UserAuth(userauth.SSHUserAuthClient):
    def __init__(self, options, *args, **kw):
        userauth.SSHUserAuthClient.__init__(self, *args, **kw)
        self.options = options


    def getPublicKey(self):
        pth = self.options['ssh-key']
        # this works with rsa too
        # just change the name here and in getPrivateKey
        if not os.path.exists(pth) or self.lastPublicKey:
            # the file doesn't exist, or we've tried a public key
            return
        k =  Key.fromFile(pth+'.pub')
        return k


    def getPrivateKey(self):
        path = self.options['ssh-key']
        return defer.succeed(Key.fromFile(path))


class SSHClient(transport.SSHClientTransport):
    """
    Yes this is a Protocol, even though it inherits from
    a class named with the word "Transport" in it - go figure...
    """
    ampProtocol = None

    def connectionMade(self):
        log.msg('SSHClient.connectionMade')
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
                                     SSHConnection(self.ampProtocol,
                                                   self.factory.options,
                                                   self.factory)))

    def getPeer(self):
        return ('FIXME',)

    def getHost(self):
        return ('FIXME',)


class SSHConnection(connection.SSHConnection):
    def __init__(self, ampProtocol, options, factory, *args, **kw):
        self.ampProtocol = ampProtocol
        self.options = options
        self.factory = factory
        connection.SSHConnection.__init__(self, *args, **kw)

    def serviceStarted(self):
        """
        This service is started once we have connected and authentcated
        successfully to the SSH Server.
        """
        log.msg('SSHConnection.serviceStarted')
        self.openChannel(AMPChannel(self.ampProtocol, conn=self))

    #def channel_session(self, windowSize, maxPacket, data):
    #    return ShellChannel(localWindow=windowSize, localMaxPacket=maxPacket,
    #                        remoteWindow=windowSize, remoteMaxPacket=maxPacket,
    #                        data=data, conn=self)

def logAndPassThrough(f):
    log.err(f)
    return f

class AMPChannel(channel.SSHChannel):
    """
    Channel, that when open, requests the AMP subsystem,
    and makes an AMP call.

    Upon successful subsystem open, we make a `Date' AMP call,
    print the results, then exit the reactor.
    """
    name = 'session' # needed for commands

    def __init__(self, ampProtocol, *args, **kw):
        channel.SSHChannel.__init__(self, *args, **kw)
        self.ampProtocol = ampProtocol
        self.buf = ''
        self.client = None
        self.session = None
        #self.protoDeferred = defer.Deferred()

    def openFailed(self, reason):
        log.msg('failed to open channel', reason)
        self.conn.transport.transport.loseConnection()

    def channelOpen(self, ignoredData):
        d = self.conn.sendRequest(self, 'subsystem', NS('amp'), wantReply=True)
        d.addCallback(self._cbSubsystem)
        d.addErrback(logAndPassThrough)
        d.addErrback(lambda f: self.conn.transport.transport.loseConnection())

    def _cbSubsystem(self, result):
        self.client = self.ampProtocol()
        self.client.makeConnection(self)
        self.dataReceived = self.client.dataReceived

        #self.protoDeferred.callback(self.client)
        #self.client.callRemote(Date
        #        ).addCallback(self._cbDone
        #        ).addErrback(self._ebFailed
        #        ).addBoth(lambda _: reactor.stop())
