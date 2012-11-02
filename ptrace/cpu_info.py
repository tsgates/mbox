"""
Constants about the CPU:

 - CPU_BIGENDIAN (bool)
 - CPU_64BITS (bool)
 - CPU_WORD_SIZE (int)
 - CPU_MAX_UINT (int)
 - CPU_PPC32 (bool)
 - CPU_PPC64 (bool)
 - CPU_I386 (bool)
 - CPU_X86_64 (bool)
 - CPU_INTEL (bool)
 - CPU_POWERPC (bool)
"""

try:
    from os import uname
    HAS_UNAME = True
except ImportError:
    HAS_UNAME = False
    from platform import architecture
from sys import byteorder
from ctypes import sizeof, c_void_p

CPU_BIGENDIAN = (byteorder == 'big')
CPU_64BITS = (sizeof(c_void_p) == 8)

if CPU_64BITS:
    CPU_WORD_SIZE = 8 # bytes
    CPU_MAX_UINT = 0xffffffffffffffff
else:
    CPU_WORD_SIZE = 4 # bytes
    CPU_MAX_UINT = 0xffffffff

if HAS_UNAME:
    # guess machine type using uname()
    _machine = uname()[4]
    CPU_PPC32 = (_machine == 'ppc')
    CPU_PPC64 = (_machine == 'ppc64')
    CPU_I386 = (_machine in ("i386", "i686"))    # compatible Intel 32 bits
    CPU_X86_64 = (_machine == "x86_64")  # compatible Intel 64 bits
    del _machine
else:
    # uname() fallback for Windows
    # I hope that your Windows doesn't run on PPC32/PPC64
    CPU_PPC32 = False
    CPU_PPC64 = False
    CPU_I386 = False
    CPU_X86_64 = False
    bits, linkage = architecture()
    if bits == '32bit':
        CPU_I386 = True
    elif bits == '64bit':
        CPU_X86_64 = True
    else:
        raise ValueError("Unknown architecture bits: %r" % bits)

CPU_INTEL = (CPU_I386 or CPU_X86_64)
CPU_POWERPC = (CPU_PPC32 or CPU_PPC64)

