# coding=utf-8
__author__ = "Dmitry Zhiltsov"
__copyright__ = "Copyright 2013, Dmitry Zhiltsov"
__license__ = "GPLv3"


import os
import shlex
import sys

from twisted.cred import checkers, credentials
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.avatar import ConchUser
from twisted.conch.ssh import common
from twisted.conch.ssh.session import SSHSession, ISession, SSHSessionProcessProtocol
from twisted.conch.ssh.factory import SSHFactory
from twisted.conch import error
from twisted.cred.portal import IRealm, Portal
from twisted.internet import reactor, defer
from twisted.internet.interfaces import IProcessTransport
from twisted.internet.error import ProcessTerminated
from twisted.python import components, log, failure
from twisted.python.failure import Failure
from twisted.conch.ssh.keys import Key
from zope import interface


log.startLogging(sys.stderr)


class VCSConfiguration:
    def __init__(self, vcs_repos_path):
        self.vcs_repos_path = vcs_repos_path

    def translate_path(self, virtual_path):
        realpath = os.path.join(self.vcs_repos_path, virtual_path.lstrip('/'))
        log.msg(realpath)
        if os.path.isdir(realpath):
            return realpath
        else:
            return False


class ErrorProcess:
    interface.implements(IProcessTransport)

    def __init__(self, proto, code, message):
        proto.makeConnection(self)
        proto.childDataReceived(2, message + '\n')
        proto.childConnectionLost(0)
        proto.childConnectionLost(1)
        proto.childConnectionLost(2)
        failure = Failure(ProcessTerminated(code))
        proto.processExited(failure)
        proto.processEnded(failure)
        # ignore all unused methods
        noop = lambda *args, **kwargs: None
        self.closeStdin = noop
        self.closeStdout = noop
        self.closeStderr = noop
        self.writeToChild = noop
        self.loseConnection = noop
        self.signalProcess = noop

    def loseConnection(self):
        pass


class PasswordChecker:
    interface.implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, checker):
        self.checker = checker

    def _cbPasswordMatch(self, matched, username):
        if matched:
            return defer.succeed(username)
        else:
            return failure.Failure(error.UnauthorizedLogin())

    def requestAvatarId(self, credentials):
        return defer.maybeDeferred(self.checker, credentials.username, credentials.password).addCallback(
            self._cbPasswordMatch, str(credentials.username))


class PublicKeyChecker(SSHPublicKeyDatabase):
    def __init__(self, checker):
        self.checker = checker

    def checkKey(self, credentials):
        return defer.maybeDeferred(self.checker, credentials.username,
                                   credentials.blob)


class VCSSession(SSHSession):
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


class VCSConchUser(ConchUser):
    def __init__(self, username, authnz, vcs_config):
        ConchUser.__init__(self)
        self.username = username
        self.authnz = authnz
        self.vcs_config = vcs_config
        self.channelLookup.update({"session": VCSSession})
        self.shell = {}
        # Find git-shell path.
        # Adapted from http://bugs.python.org/file15381/shutil_which.patch
        self.path = os.environ.get("PATH", os.defpath)
        self.shell['git'] = self._shells_find('git-shell')
        # self.shell['hd'] = self._shells_find('hg')
        self.shell['hg'] = '/usr/local/bin/hg'
    def _shells_find(self, cmd_name):
        for directory in self.path.split(os.pathsep):
            full_path = os.path.join(directory, cmd_name)
            if (os.path.exists(full_path) and
                    os.access(full_path, (os.F_OK | os.X_OK))):
                return full_path

    def logout(self):
        pass


class GitSession:
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


class GitRealm:
    interface.implements(IRealm)

    def __init__(self, authnz, vcs_config):
        self.authnz = authnz
        self.vcs_config = vcs_config

    def requestAvatar(self, username, mind, *interfaces):
        user = VCSConchUser(username, self.authnz, self.vcs_config)
        return interfaces[0], user, user.logout


class BaseAuthnz:

    def __init__(self, pkeys_file=None):
        self.methods = {}
        self.pkeys_file = pkeys_file
        self.methods["password"] = True
        self.methods["publick_key"] = False

    def checker_registred(self, method):
        return method[method]

    def can_read(self, username, gitpath):
        pass

    def can_write(self, username, gitpath):
        pass

    def check_password(self, username, password):
        pass

    def check_publickey(self, username, keyblob):
        if self.pkeys_file:
            try:
                with open(self.pkeys_file, 'rb') as f:
                    for line in f:
                        try:
                            user, key = line.split(':', 1)
                            if (username == user.strip() and
                                keyblob == Key.fromString(data=key.strip()
                                                               ).blob()):
                                return True
                        except:
                            log.err(None, "Loading key failed")
            except:
                log.err(None, 'No key file')
        return False


def create_factory(private_keys, public_keys, authnz_instanse, vcs_configuration):
    components.registerAdapter(GitSession, VCSConchUser, ISession)

    class VCSServer(SSHFactory):
        publicKeys = public_keys
        privateKeys = private_keys
        authnz = authnz_instanse
        vcs_config = VCSConfiguration(vcs_configuration)
        portal = Portal(GitRealm(authnz, vcs_config))
        if hasattr(authnz, "check_password"):
            log.msg("Registering PasswordChecker")
            portal.registerChecker(PasswordChecker(authnz.check_password))
        if hasattr(authnz, 'check_publickey'):
            log.msg("Registering PublicKeyChecker")
            portal.registerChecker(PublicKeyChecker(authnz.check_publickey))

    #class VCSGitServer(GitFactory)
    return VCSServer