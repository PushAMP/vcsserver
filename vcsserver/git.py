# coding=utf-8
__author__ = "Dmitry Zhiltsov"
__copyright__ = "Copyright 2013, Dmitry Zhiltsov"
__license__ = "GPLv3"


from zope.interface import implements
from twisted.python import log

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, ProcessProtocol, Factory
from twisted.internet.interfaces import IPushProducer
from twisted.cred.portal import Portal

from .common import shell_find, VCSConfiguration
from .ssh import PasswordChecker, VCSRealm


class GitProcessProtocol(ProcessProtocol):
    def __init__(self, gitprotocol):
        self.gitprotocol = gitprotocol

    def connectionMade(self):
        # twisted.internet.process.Process seems to not fully
        # implement IPushProducer since stopProducing is missing
        # therefore patch in a dummy one
        if not hasattr(self.transport, "stopProducing"):
            setattr(self.transport, "stopProducing",
                    lambda: self.transport.loseConnection())

        self.transport.registerProducer(self.gitprotocol, True)
        self.gitprotocol.transport.registerProducer(self.transport, True)

        self.gitprotocol.resumeProducing()

    def outReceived(self, data):
        self.gitprotocol.transport.write(data)

    def errReceived(self, data):
        self.gitprotocol.transport.write(data)

    def processEnded(self, status):
        log.msg("Git ended with %r" % status.value.message)
        self.gitprotocol.transport.unregisterProducer()
        self.gitprotocol.transport.loseConnection()


class GitProtocol(Protocol):
    implements(IPushProducer)

    __buffer = ''
    paused = False
    requestReceived = False

    def __init__(self, authnz, git_configuration):
        self.authnz = authnz
        self.vcs_configuration = git_configuration

    def connectionMade(self):
        print self.transport.getPeer()

    def dataReceived(self, data):
        self.__buffer = self.__buffer + data

        while not self.paused and len(self.__buffer) >= 4:
            try:
                pktlen = int(self.__buffer[:4], 16)
            except ValueError:
                return self.sendErrorAndDisconnect(
                    "ERR Invalid Paket Length: " + self.__buffer[:4])

            if pktlen == 0:  # flush packet 0000
                pktlen = 4

            # The git protocol specifies bounds for the packet length
            if pktlen < 4 or pktlen > 65524:
                return self.sendErrorAndDisconnect(
                    "ERR Invalid Paket Length: " + self.__buffer[:4])

            # Do we have the complete packet in the buffer?
            if pktlen > len(self.__buffer):
                return

            packet = self.__buffer[:pktlen]
            self.__buffer = self.__buffer[pktlen:]
            self.packetReceived(packet)

    def packetReceived(self, data):
        if not self.requestReceived:
            payload = data[4:]

            # git:// would also support other RPC methods, but since
            # there is no authentication, only allow cloning aka
            # git-upload-pack
            if not payload.startswith("git-upload-pack"):
                return self.sendErrorAndDisconnect(
                    "ERR Request not supported. "
                    "Only git-upload-pack will be accepted")

            try:
                rpc_params = payload[len("git-upload-pack "):].split("\0")
                path, unused_host, unused_eol = rpc_params
            except ValueError:
                return self.sendErrorAndDisconnect(
                    "ERR Unable to parse request line")

            path_info = self.vcs_configuration.translate_path(path)
            if path_info is None:
                return self.sendErrorAndDisconnect("ERR Repository not found")

            if not self.authnz.can_read(None, path_info):
                return self.sendErrorAndDisconnect(
                    "ERR Repository does not allow anonymous read access")

            # wait with data until we have a connection to the process
            self.pauseProducing()
            self.requestReceived = True
            self.process = GitProcessProtocol(self)

            #gitbinary = self.git_configuration.git_binary
            gitbinary = shell_find('git-shell')
            #cmdargs = ['git', 'upload-pack', path_info]
            cmdargs= [gitbinary, '-c', 'git-upload-pack' + ' \'' + path_info + '\'']
            log.msg("Spawning %s with args %r" % (gitbinary, cmdargs))

            reactor.spawnProcess(self.process, gitbinary, cmdargs)

        else:
            self.process.transport.write(data)

    def sendErrorAndDisconnect(self, msg):
        self.transport.write(self._git_packet(msg=msg))
        self.transport.loseConnection()

        # return None so it can be used
        # in a return statement in dataReceived for simplicity
        return None

    def pauseProducing(self):
        self.paused = True
        self.transport.pauseProducing()

    def resumeProducing(self):
        self.paused = False
        self.transport.resumeProducing()
        self.dataReceived('')

    def stopProducing(self):
        # Only pause and don't call self.transport.stopProducing
        # since stopProducing will call loseConnection. This
        # can happen when git closes stdin but there is still
        # data on stdout/stderr
        # loseConnection will be called when the process ends
        # and everything has been written
        self.paused = True

    def _git_packet(self, msg=None):
        if msg is None:
            return '0000'
        return str(hex(len(msg) + 4)[2:].rjust(4, '0')) + msg


class GitFactory(Factory):
    authnz = None
    vcs_configuration = None
    allow_ip = ['127.0.0.1']
    #def __init__(self, authnz, git_configuration):


    def buildProtocol(self, addr):
        if addr.host in self.allow_ip:
            log.msg('Access allow for %s' % addr.host)
            return GitProtocol(self.authnz, self.vcs_configuration)
        log.err('Access denied for %s' % addr.host)
        return None

def create_factory(authnz_instanse, git_configuration, allow_ips):

    class VCSGitServer(GitFactory):
        authnz = authnz_instanse
        vcs_configuration = VCSConfiguration(git_configuration)
        portal = Portal(VCSRealm(authnz, vcs_configuration))
        log.msg("Registering IPChecker")
        portal.registerChecker(PasswordChecker(authnz.check_ip))
        allow_ip = allow_ips
    return VCSGitServer
