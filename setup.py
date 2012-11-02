#!/usr/bin/env python

# Produce to release a new version:
#  - ./test_doc.py
#  - test gdb.py
#  - test strace.py
#  - check version in ptrace/version.py
#  - set release date in the ChangeLog
#  - hg ci
#  - hg tag python-ptrace-x.y
#  - update version in ptrace/version.py
#  - hg ci
#  - hg push
#  - ./setup.py sdist register upload
#  - update the website home page (url, md5 and news)
#    https://bitbucket.org/haypo/python-ptrace/wiki/Home
#
# After the release:
#  - set version to n+1 (ptrace/version.py)
#  - add a new empty section in the changelog for version n+1

from __future__ import with_statement

MODULES = ["ptrace", "ptrace.binding", "ptrace.syscall", "ptrace.debugger"]

SCRIPTS = ("strace.py", "gdb.py")

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
]

with open('README') as fp:
    LONG_DESCRIPTION = fp.read()
with open('ChangeLog') as fp:
    LONG_DESCRIPTION += fp.read()

from imp import load_source
from os import path
from sys import argv
from distutils.core import setup

ptrace = load_source("version", path.join("ptrace", "version.py"))
PACKAGES = {}
for name in MODULES:
    PACKAGES[name] = name.replace(".", "/")

install_options = {
    "name": ptrace.PACKAGE,
    "version": ptrace.VERSION,
    "url": ptrace.WEBSITE,
    "download_url": ptrace.WEBSITE,
    "author": "Victor Stinner",
    "description": "python binding of ptrace",
    "long_description": LONG_DESCRIPTION,
    "classifiers": CLASSIFIERS,
    "license": ptrace.LICENSE,
    "packages": PACKAGES.keys(),
    "package_dir": PACKAGES,
    "scripts": SCRIPTS,
}

# Python 3: run 2to3
try:
    from distutils.command.build_py import build_py_2to3
    from distutils.command.build_scripts import build_scripts_2to3
except ImportError:
    pass
else:
    install_options['cmdclass'] = {
        'build_py': build_py_2to3,
        'build_scripts': build_scripts_2to3,
    }

setup(**install_options)
