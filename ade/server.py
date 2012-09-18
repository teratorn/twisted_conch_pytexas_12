"""
AmpDateEcho

An SSH "amp" subsystem, providing date and echo services.

http://amp-protocol.net/OverSSH
"""
from twisted.protocols import amp

from twisted.internet.protocol import Protocol
from twisted.internet import defer

from twisted.application import service
from twisted.application import internet
from twisted.python.filepath import FilePath
from twisted.python import log

from twisted.cred.portal import Portal
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.error import UnhandledCredentials
from twisted.python import failure, reflect, log
from twisted.conch.manhole_ssh import ConchFactory
from twisted.cred.credentials import ISSHPrivateKey
from twisted.conch.manhole_ssh import TerminalRealm
from twisted.conch.ssh.factory import SSHFactory
from twisted.conch.ssh.session import (
    SSHSession, SSHSessionProcessProtocol, wrapProtocol)
from twisted.conch.interfaces import IConchUser
from twisted.conch.avatar import ConchUser
from twisted.conch.ssh import connection
from twisted.conch.ssh.keys import Key
from twisted.conch.ssh import keys
from twisted.conch.ssh import channel
from twisted.conch.ssh import common
from twisted.conch import error
from twisted.cred import portal

from zope.interface import implements

import base64
import binascii
import datetime
import struct
import os


import tickets

class Echo(amp.Command):
    arguments = [('msg', amp.String())]

    response = [('echo', amp.String())]


class Date(amp.Command):
    response = [('date', amp.DateTime())]


class OfferShell(amp.Command):
    response = [('ticket', amp.String())]


class EchoDateProtocol(amp.AMP):
    ticket = None

    def __init__(self, avatar):
        amp.AMP.__init__(self)
        self.avatar = avatar
        self.options = avatar.options
        self.factory = avatar.factory

    @Echo.responder
    def echo(self, msg=None):
        log.msg("Echoing %r to %s" % (msg, self.transport.getPeer()))

        return {'echo' : msg}

    @Date.responder
    def date(self):
        log.msg("Serviced Date request.")

        #return {'date' : datetime.datetime.utcnow()}
        d = datetime.datetime.utcnow()
        d = d.replace(tzinfo=amp.utc)
        return {'date' : d}

    def connectionMade(self):
        log.msg("Made conn.")

    def connectionLost(self, reason):
        log.msg("Lost conn.")


    @OfferShell.responder
    def offershell(self):
        log.msg("OfferShell command received.")

        ticket = tickets.newTicket()
        self.factory.tickets[ticket] = (self.avatar.conn, self)
        self.ticket = ticket
        log.msg("Shell slave client accepted and assigned ticket %s" % (ticket,))
        return {'ticket' : ticket}


    def connectionLost(self, reason):
        if self.ticket in self.factory.tickets:
            del self.factory.tickets[self.ticket]


class AMPSession(SSHSession):
    """
    Channel that supports an AMP subsystem.
    """
    name = 'session' # require for ssh spec.

    def request_pty_req(self, data):
        log.msg('Ignoring non-critical pty request')
        return True

    def request_subsystem(self, data):
        subsystem, junk = common.getNS(data)
        if subsystem == 'amp':
            #import pdb; pdb.set_trace()
            protocol = EchoDateProtocol(self.avatar)
            transport = SSHSessionProcessProtocol(self)
            protocol.makeConnection(transport)
            transport.makeConnection(wrapProtocol(protocol))
            self.client = transport
            return True # subsystem request OK

        else:
            log.msg('Unknown subsystem requested: %r' % (subsystem,))
            return False # Fail subsystem request.


    #def request_shell(self, data):


class SimpleRealm(object):
    def __init__(self, tickets, options, factory):
        self.tickets = tickets
        self.factory = factory

    def requestAvatar(self, username, mind, *interfaces):
        """"
        The connection has already been authenticated at this point. Our job
        is to return some objects representing the logged in user.

        `username' is also known as the Avatar ID in `twisted.cred' terminology.
        """

        try:
            # treat username as an OTP and attempt 
            transport, protocol = self.tickets.pop(username)

            # reset routing ticket since it is one-time only.
            ticket = tickets.newTicket()
            self.tickets[ticket] = (transport, protocol)
            log.msg("Reset routing ticket from %s to %s" % (username, ticket,))

            u = ConchUser()
           
            # Add a custom field to indicate that this connection
            # is going to be connected (routed) using this ticket.
            u._connectTo = (transport, protocol)

            u.factory = self.factory
            u.options = self.factory.options
            return IConchUser, u, lambda:None

        except KeyError:
            log.msg('Username %r not recognized as access ticket. Connecting to public AMP subsystem only!' % (username,))
            # logged in user gets access to AMP subsystem only. No shells.
            u = ConchUser()
            u.factory = self.factory
            u.options = self.factory.options
            u.channelLookup['session'] = AMPSession
            return IConchUser, u, lambda:None



class ProxyChannel(channel.SSHChannel):
    def __init__(self, *args, **kw):
        channel.SSHChannel.__init__(self, *args, **kw)
        self.openDeferred = defer.Deferred()

    def channelOpen(self, specificData):
        channel.SSHChannel.channelOpen(self, specificData)
        self.openDeferred.callback(None)

    def openFailed(self, reason):
        channel.SSHChannel.openFailed(self, reason)
        self.openDeferred.errback(reason)

    def proxyTo(self, proxyChan):
        self.proxyChan = proxyChan

    def dataReceived(self, data):
        self.proxyChan.write(data)

    def extReceived(self, data):
        self.proxyChan.writeExtended(data)

    def eofReceived(self):
        self.proxyChan.conn.sendEOF(self.proxyChan)

    def closeReceived(self):
        self.proxyChan.conn.sendClose(self.proxyChan)

    def requestReceived(self, requestType, data):
        d = self.proxyChan.conn.sendRequest(self.proxyChan, requestType,
                                            data, wantReply=True)
        return d.addCallback(lambda _: True)



class SSHConnection(connection.SSHConnection):
    proxyConn = None
    def serviceStarted(self):
        connection.SSHConnection.serviceStarted(self)

        if getattr(self.transport, 'avatar', None) is not None:
            _connectTo = getattr(self.transport.avatar, '_connectTo', None)
            if _connectTo is not None:
                if _connectTo is not None:
                    self.proxyConn = _connectTo[0]
                    print 'started proxying to', self.proxyConn
                else:
                    print 'ticket not found - dropping connection'
                    self.transport.loseConnection()


    def getChannel(self, channelType, windowSize, maxPacket, data):
        print 'getChannel', channelType, windowSize, maxPacket, data

        if self.proxyConn is None:
            return connection.SSHConnection.getChannel(self,
                                                       channelType,
                                                       windowSize,
                                                       maxPacket,
                                                       data)
        else:
            print 'proxying channel request...'
            # open the same type of channel on the proxy peer
            proxyChan = ProxyChannel(localWindow=windowSize,
                                    localMaxPacket=maxPacket,
                                    remoteWindow=windowSize,
                                    remoteMaxPacket=maxPacket,
                                    data=data,
                                    conn=self.proxyConn)
            proxyChan.name = channelType

            ourChan = ProxyChannel(localWindow=windowSize,
                                   localMaxPacket=maxPacket,
                                   remoteWindow=windowSize,
                                   remoteMaxPacket=maxPacket,
                                   data=data,
                                   conn=self)
            ourChan.name = channelType

            proxyChan.proxyTo(ourChan)
            ourChan.proxyTo(proxyChan)

            self.proxyConn.openChannel(proxyChan, extra=data)

            return proxyChan.openDeferred.addCallback(lambda _: ourChan)


    def ssh_CHANNEL_OPEN(self, packet):
        """
        The other side wants to get a channel.  Payload::
            string  channel name
            uint32  remote channel number
            uint32  remote window size
            uint32  remote maximum packet size
            <channel specific data>

        We get a channel from self.getChannel(), give it a local channel number
        and notify the other side.  Then notify the channel, by calling its
        channelOpen method.
        """
        channelType, rest = common.getNS(packet)
        senderChannel, windowSize, maxPacket = struct.unpack('>3L', rest[:12])
        packet = rest[12:]

        d = defer.maybeDeferred(self.getChannel, channelType, windowSize,
                                maxPacket, packet)
        d.addCallback(self._cbGotChannel, senderChannel, packet)
        d.addErrback(self._ebGotChannelFailed, senderChannel)

    def _cbGotChannel(self, channel, senderChannel, packet):
        localChannel = self.localChannelID
        self.localChannelID += 1
        channel.id = localChannel
        self.channels[localChannel] = channel
        self.channelsToRemoteChannel[channel] = senderChannel
        self.localToRemoteChannel[localChannel] = senderChannel
        self.transport.sendPacket(connection.MSG_CHANNEL_OPEN_CONFIRMATION,
            struct.pack('>4L', senderChannel, localChannel,
                channel.localWindowSize,
                channel.localMaxPacket)+channel.specificData)
        log.callWithLogger(channel, channel.channelOpen, packet)

    def _ebGotChannelFailed(self, f, senderChannel):
        log.msg('channel open failed')
        log.err(f)
        if f.check(error.ConchError):
            textualInfo, reason = f.value.args
            if isinstance(textualInfo, (int, long)):
                # See #3657 and #3071
                textualInfo, reason = reason, textualInfo
        else:
            reason = connection.OPEN_CONNECT_FAILED
            textualInfo = "unknown failure"
        self.transport.sendPacket(
            connection.MSG_CHANNEL_OPEN_FAILURE,
            struct.pack('>2L', senderChannel, reason) +
            common.NS(textualInfo) + common.NS(''))


class AMPSSHFactory(SSHFactory):
    def __init__(self, tickets, options):
        self.tickets = tickets
        self.options = options


class AMPSSHService(internet.TCPServer):
    def __init__(self, options):

        self.options = options
        
        # load private key
        with open(options['host-key']) as privateBlobFile:
            privateBlob = privateBlobFile.read()
            privateKey = Key.fromString(data=privateBlob)

        # load public key
        with open(options['host-key']+'.pub') as publicBlobFile:
            publicBlob = publicBlobFile.read()
            publicKey = Key.fromString(data=publicBlob)

        tickets = {}
        factory = AMPSSHFactory(tickets, self.options)
        factory.services['ssh-connection'] = SSHConnection

        # Load in keys the way SSHFactory expects them.
        factory.privateKeys = {'ssh-rsa': privateKey}
        factory.publicKeys = {'ssh-rsa': publicKey}

        # Give it a portal to authenticate clients with
        factory.portal = Portal(SimpleRealm(tickets, options, factory))

        # validate against keys in authorized_keys files
        checker = AuthorizedKeys(options['authorized-keys'])
        factory.portal.registerChecker(checker)

        # init TCPServer with port and factory.
        internet.TCPServer.__init__(self, options['ssh-port'], factory)

        # remember for future reference
        self.factory = factory


class AuthorizedKeys:
    """
    Checker that authenticates SSH public keys, based on public keys listed in
    authorized_keys and authorized_keys2 files in user .ssh/ directories.
    """
    implements(ICredentialsChecker)

    credentialInterfaces = (ISSHPrivateKey,)
    def __init__(self, authorizedKeys):
        self._filePath = FilePath(authorizedKeys)
        #self._keys = set()
        #with open(authorizedKeys, 'rb') as f:
        #    for line in f:
        #        type, b64text, comment = line.split()
        #        self._keys.add(b64text.decode('base64'))


    #_userdb = pwd

    def requestAvatarId(self, credentials):
        d = defer.maybeDeferred(self.checkKey, credentials)
        d.addCallback(self._cbRequestAvatarId, credentials)
        d.addErrback(self._ebRequestAvatarId)
        return d

    def _cbRequestAvatarId(self, validKey, credentials):
        """
        Check whether the credentials themselves are valid, now that we know
        if the key matches the user.

        @param validKey: A boolean indicating whether or not the public key
            matches a key in the user's authorized_keys file.

        @param credentials: The credentials offered by the user.
        @type credentials: L{ISSHPrivateKey} provider

        @raise UnauthorizedLogin: (as a failure) if the key does not match the
            user in C{credentials}. Also raised if the user provides an invalid
            signature.

        @raise ValidPublicKey: (as a failure) if the key matches the user but
            the credentials do not include a signature. See
            L{error.ValidPublicKey} for more information.

        @return: The user's username, if authentication was successful.
        """
        if not validKey:
            return failure.Failure(UnauthorizedLogin("invalid key"))
        if not credentials.signature:
            return failure.Failure(error.ValidPublicKey())
        else:
            try:
                pubKey = keys.Key.fromString(credentials.blob)
                if pubKey.verify(credentials.signature, credentials.sigData):
                    return credentials.username
            except: # any error should be treated as a failed login
                log.err()
                return failure.Failure(UnauthorizedLogin('error while verifying key'))
        return failure.Failure(UnauthorizedLogin("unable to verify key"))


    def getAuthorizedKeysFiles(self, credentials):
        """
        Return a list of L{FilePath} instances for I{authorized_keys} files
        which might contain information about authorized keys for the given
        credentials.

        On OpenSSH servers, the default location of the file containing the
        list of authorized public keys is
        U{$HOME/.ssh/authorized_keys<http://www.openbsd.org/cgi-bin/man.cgi?query=sshd_config>}.

        I{$HOME/.ssh/authorized_keys2} is also returned, though it has been
        U{deprecated by OpenSSH since
        2001<http://marc.info/?m=100508718416162>}.

        @return: A list of L{FilePath} instances to files with the authorized keys.
        """
        #pwent = self._userdb.getpwnam(credentials.username)
        #root = FilePath(pwent.pw_dir).child('.ssh')
        #files = ['authorized_keys', 'authorized_keys2']
        #return [root.child(f) for f in files]
        return self._files


    def checkKey(self, credentials):
        for line in self._filePath.open():
            l2 = line.split()
            if len(l2) < 2:
                continue
            try:
                if base64.decodestring(l2[1]) == credentials.blob:
                    return True
            except binascii.Error:
                continue
        return False

    def _ebRequestAvatarId(self, f):
        if not f.check(UnauthorizedLogin):
            log.msg(f)
            return failure.Failure(UnauthorizedLogin("unable to get avatar id"))
        return f
