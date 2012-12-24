__all__ = ["install_seccomp"]

import os

from os.path import join
from os.path import dirname

from ctypes import cdll

dll = join(dirname(__file__), "./libseccomp.so")
lib = cdll.LoadLibrary(dll)

install_seccomp = lib.install_seccomp