# coding=utf-8
__author__ = "Dmitry Zhiltsov"
__copyright__ = "Copyright 2013, Dmitry Zhiltsov"
__license__ = "GPLv3"

import sys
import os

from twisted.python.failure import Failure
from twisted.internet import defer
from twisted.internet.interfaces import IProcessTransport
from twisted.internet.error import ProcessTerminated
from twisted.conch.ssh.keys import Key
from twisted.python import log, failure
from twisted.conch import error, avatar
from twisted.cred import checkers, credentials

from zope import interface


log.startLogging(sys.stderr)


def shell_find(cmd_name):
    path = os.environ.get("PATH", os.defpath)
    for directory in path.split(os.pathsep):
        full_path = os.path.join(directory, cmd_name)
        if (os.path.exists(full_path) and
                os.access(full_path, (os.F_OK | os.X_OK))):
            return full_path


class BaseAuthnz(object):
    methods = {"password": True, "publick_key": False, 'ip': False}

    def __init__(self, pkeys_file=None):
        self.pkeys_file = pkeys_file

    @staticmethod
    def checker_registred(method):
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


class VCSConfiguration(object):
    def __init__(self, vcs_repos_path):
        self.vcs_repos_path = vcs_repos_path

    def translate_path(self, virtual_path):
        realpath = os.path.join(self.vcs_repos_path, virtual_path.lstrip('/'))
        log.msg(realpath)
        if os.path.isdir(realpath):
            return realpath
        else:
            return False


class ErrorProcess(object):
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


class PasswordChecker(object):
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


class VCSConchUser(avatar.ConchUser):
    channel_session = None

    def __init__(self, username, authnz, vcs_config):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.authnz = authnz
        self.vcs_config = vcs_config
        self.channelLookup.update({"session": self.channel_session})
        self.shell = {}
        # Find git-shell path.
        # Adapted from http://bugs.python.org/file15381/shutil_which.patch
        self.path = os.environ.get("PATH", os.defpath)
        self.shell['git'] = self._shells_find('git-shell')
        # self.shell['hd'] = self._shells_find('hg')
        self.shell['hg'] = self._shells_find('hg')

    def _shells_find(self, cmd_name):
        return shell_find(cmd_name=cmd_name)

    def logout(self):
        pass