# coding=utf-8
__author__ = "Dmitry Zhiltsov"
__copyright__ = "Copyright 2013, Dmitry Zhiltsov"
__license__ = "BSD"

import sys
import os
from ConfigParser import ConfigParser

from pymongo import MongoClient, errors
from twisted.python import log
from twisted.internet import reactor
from twisted.application import internet, service
from twisted.conch.ssh.keys import Key
from twisted.python.log import ILogObserver, FileLogObserver
from twisted.python.logfile import DailyLogFile

#Import vcsshd-lib library
from vcssshd import create_factory, BaseAuthnz

#Get config from file (you can implement it as you wish)
config = ConfigParser()
config.read(['/etc/vcssshd/vcssshd.ini', os.path.expanduser('~/vcssshd.ini')])

#Required params
publicKey = open(config.get('SSH', 'PUBLIC_KEY')).read()
privateKey = open(config.get('SSH', 'PRIVATE_KEY')).read()
SSH_SERVER_PORT = config.getint('SSH', 'SERVER_PORT')
SSH_LOG_PATH = config.get('SSH', 'SSH_LOG_PATH')

#Path where your repos located, if you don't need to use virtual path set the '/'
VCS_REPOS_PATH = config.get('VCS', 'VCS_REPOS_PATH')

#Your own params
DOMAIN_NAME = config.get('LDAP', 'DOMAIN_NAME')
LDAP_SERVER = config.get('LDAP', 'LDAP_SERVER')
MONGO_DB = config.get('MONGO', 'DATABASE')
MONGO_COLL = config.get('MONGO', 'COLLECTION')



try:
    conn = MongoClient()
    db = conn['vcs']
    col = db['repos']
    col_key = db['pkeys']
    log.msg('Connected to MongoDB')
except errors.ConnectionFailurea as exc:
    log.err('Failed connect to MongoDB. Reason: {0}'.format(e))
    sys.exit()

#Here we subclass the base class implementing authorization and ACL
#You need to redefine can_read, can_write and check_password methods
class LdapAutnz(BaseAuthnz):
    # If method return True, user can read repository (e.g. git pull, hg pull, git/hg clone, etc)
    def can_read(self, username, gitpath):
        if col.find_one({'path': gitpath, "$or": [{"users_w": username}, {"users_r": username}]},{}):
            return True
        else:
            return False
    # If method return True, user can read and write into repository (e.g. git push, hg push, git pull, hg pull,etc)
    def can_write(self, username, gitpath):
        if col.find_one({'path': gitpath, "users_w": username}):
            return True
        else:
            return False
    # If method return True, user has access to your ssh deamon
    def check_password(self, username, password):
        return True

    def check_publickey(self, username, keyblob):
        if self.pkeys_file:
            try:
                key = col_key.find_one({"_id": username}, {"_id": False, "key": True})['key']
                if (keyblob == Key.fromString(data=key.strip()).blob()):
                    return True
                log.err(None, "Loading key failed")
            except:
                log.err(None, 'Get key failed')
        return False

#Here we create application factory. All params required
ssh_factory = create_factory(public_keys={'ssh-rsa': Key.fromString(data=publicKey)},
                             private_keys={'ssh-rsa': Key.fromString(data=privateKey)},
                             authnz_instanse=LdapAutnz(pkeys_file="/Users/dmitryziltcov/keyfile"),
                             vcs_configuration=VCS_REPOS_PATH)
#And start your factory
#For other startup options read offical Twisted documentation
application = service.Application('vcssshd')
factory = ssh_factory()
logfile = DailyLogFile("vcssshd.log", SSH_LOG_PATH)
application.setComponent(ILogObserver, FileLogObserver(logfile).emit)
internet.TCPServer(SSH_SERVER_PORT, factory).setServiceParent(service.IServiceCollection(application))

if __name__ == '__main__':
    reactor.listenTCP(SSH_SERVER_PORT, factory)
    reactor.run()


