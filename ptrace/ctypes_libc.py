"""
Load the system C library. Variables:
 - LIBC_FILENAME: the C library filename
 - libc: the loaded library
"""

from ctypes import cdll
from ctypes.util import find_library

LIBC_FILENAME = find_library('c')
libc = cdll.LoadLibrary(LIBC_FILENAME)

