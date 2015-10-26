# coding=utf-8
__author__ = "Dmitry Zhiltsov"
__copyright__ = "Copyright 2013, Dmitry Zhiltsov"
__license__ = "GPLv3"


import shlex
import sys

from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh import common
from twisted.conch.ssh.session import SSHSession, ISession, SSHSessionProcessProtocol
from twisted.conch.ssh.factory import SSHFactory

from twisted.cred.portal import IRealm, Portal
from twisted.internet import reactor, defer
from twisted.python import components, log

from zope import interface

from .common import VCSConfiguration, ErrorProcess, PasswordChecker, VCSConchUser


log.startLogging(sys.stderr)


class PublicKeyChecker(SSHPublicKeyDatabase):
    def __init__(self, checker):
        self.checker = checker

    def checkKey(self, credentials):
        return defer.maybeDeferred(self.checker, credentials.username,
                                   credentials.blob)


class VCSSSHSession(SSHSession):
    def __init__(self, *args, **kw):
        SSHSession.__init__(self, *args, **kw)

    def request_exec(self, data):
        if not self.session:
            self.session = ISession(self.avatar)
        f, data = common.getNS(data)
        log.msg('executing command "%s"' % f)
        try:
            pp = VCSProcessProtocol(self)
            self.session.execCommand(pp, f)
        except:
            log.deferr()
            return 0
        else:
            self.client = pp
            return 1


class VCSProcessProtocol(SSHSessionProcessProtocol):
    def __init__(self, session):
        SSHSessionProcessProtocol.__init__(self, session)
        self.session = session

    def outReceived(self, data):
        # log.msg(len(data))
        # if len(data) < 8192:
        #     log.msg(data)
        SSHSessionProcessProtocol.outReceived(self, data)

    def inConnectionLost(self):
        # log.msg('TPP.inConnectionLost()')
        SSHSessionProcessProtocol.inConnectionLost(self)

    def outConnectionLost(self):
        pass


class VCSSSHConchUser(VCSConchUser):
    channel_session = VCSSSHSession


class VCSSSHSession(object):
    interface.implements(ISession)

    def __init__(self, user):
        self.user = user
        self.pptrans = None

    def execCommand(self, proto, cmd):
        cmdparts = shlex.split(cmd)
        rpc = cmdparts[0]
        vpath = cmdparts[-1]
        if rpc in ['git-upload-pack', 'git-receive-pack']:
            shell = 'git'
            vpath = cmdparts[-1]
            realpath = self.user.vcs_config.translate_path(vpath)
            if rpc == 'git-upload-pack' and not self.user.authnz.can_read(self.user.username, vpath):
                log.msg('User %s tried to access %s but does not have read permissions' % (self.user.username, vpath))
                return self._kill_connection(proto, "You don't have read permissions")
            if rpc == 'git-receive-pack' and not self.user.authnz.can_write(self.user.username, vpath):
                log.msg('User %s tried to access %s but does not have write permissions' % (self.user.username, vpath))
                return self._kill_connection(proto, "You don't have write permissions")
            cmdargs = [self.user.shell[shell], '-c', rpc + ' \'' + realpath + '\'']
        elif rpc == 'hg':
            shell = 'hg'
            vpath = '/' + cmdparts[2]
            realpath = self.user.vcs_config.translate_path(vpath)
            log.msg('User %s tried to access Hg repo %s ' % (self.user.username, vpath))
            cmdargs = [self.user.shell[shell], '-R', realpath, 'serve', '--stdio']
            if self.user.authnz.can_read(self.user.username, vpath) \
                and not self.user.authnz.can_write(self.user.username, vpath):
                cmdargs += [
                    '--config',
                    'hooks.prechangegroup.hg-ssh=python -c "import sys; print >> sys.stderr, (\'Permission denied\'); sys.exit(2)"',
                    '--config',
                    'hooks.prepushkey.hg-ssh=python -c "import sys; print >> sys.stderr, (\'Permission denied\'); sys.exit(2)'
                ]
                log.msg("User %s can read Hg repo %s" % (self.user.username, vpath))
            else:
                if not self.user.authnz.can_read:
                    log.msg('User %s tried to access %s but does not have read permissions' % (self.user.username, vpath))
                    return self._kill_connection(proto, "You don't have read permissions")
            if self.user.authnz.can_write(self.user.username, vpath):
                log.msg("Can write")
        else:
            log.err('Not Git or Hg  RPC: ' + rpc)
            return self._kill_connection(proto, "Unknown RPC")
        log.msg("Spawning %s with args %r" % (self.user.shell[shell], cmdargs))
        self.pptrans = reactor.spawnProcess(proto, self.user.shell[shell], cmdargs)

    def openShell(self, trans):
        self._kill_connection(trans, "Shell access not allowed")

    def _kill_connection(self, proto, msg):
        ErrorProcess(proto, 128, msg)

    def eofReceived(self):
        if self.pptrans:
            self.pptrans.closeStdin()

    def closed(self):
        pass

    def getPty(self, *args):
        pass


class VCSRealm(object):
    interface.implements(IRealm)

    def __init__(self, authnz, vcs_config):
        self.authnz = authnz
        self.vcs_config = vcs_config

    def requestAvatar(self, username, mind, *interfaces):
        user = VCSSSHConchUser(username, self.authnz, self.vcs_config)
        return interfaces[0], user, user.logout


def create_factory(private_keys, public_keys, authnz_instanse, vcs_configuration):
    components.registerAdapter(VCSSSHSession, VCSSSHConchUser, ISession)

    class VCSSSHServer(SSHFactory):
        publicKeys = public_keys
        privateKeys = private_keys
        authnz = authnz_instanse
        vcs_config = VCSConfiguration(vcs_configuration)
        portal = Portal(VCSRealm(authnz, vcs_config))
        if hasattr(authnz, "check_password"):
            log.msg("Registering PasswordChecker")
            portal.registerChecker(PasswordChecker(authnz.check_password))
        if hasattr(authnz, 'check_publickey'):
            log.msg("Registering PublicKeyChecker")
            portal.registerChecker(PublicKeyChecker(authnz.check_publickey))
    return VCSSSHServer