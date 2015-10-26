vcssshd-lib
===========

vcssshd-lib is library for easy and fast creation of an ssh demon for popular VCSs (Mercurial and Git).
This library uses Twisted framework.

Features
--------

* Work on any POSIX compatible OSes
* Works with any clients
* Support for repositories locataed at virtual path
* Easy usage of your own authetication and ACL

Installation
------------
Install the extension with one of the following commands:

	pip install vcssshd
	
or download the source code from here and run command:

	python setup.py build
	python setup.py install


Sample usage
-------------

See example/run.py in source code.
You can run example (or own daemon) of the following command

twistd -y run.py -u 500 -g 500 --pidfile=/var/run/twistd