__all__ = ["install_seccomp"]

import os

from os.path import join
from os.path import dirname

from ctypes import cdll

# load seccomp installer
dll = join(dirname(__file__), "./libseccomp.so")
try:
    lib = cdll.LoadLibrary(dll)
except:
    print "make libseccomp.so"
    exit(1)

install_seccomp = lib.install_seccomp