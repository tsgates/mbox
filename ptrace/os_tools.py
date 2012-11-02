"""
Constants about the operating system:

 - RUNNING_PYPY (bool)
 - RUNNING_WINDOWS (bool)
 - RUNNING_LINUX (bool)
 - RUNNING_FREEBSD (bool)
 - RUNNING_OPENBSD (bool)
 - RUNNING_MACOSX (bool)
 - RUNNING_BSD (bool)
 - HAS_PROC (bool)
 - HAS_PTRACE (bool)
"""

from sys import platform, version, version_info

RUNNING_PYTHON3 = version_info[0] == 3
RUNNING_PYPY = ("pypy" in version.lower())
RUNNING_WINDOWS = (platform == 'win32')
RUNNING_LINUX = (platform == 'linux2')
RUNNING_FREEBSD = (platform.startswith('freebsd')
                   or platform.startswith('gnukfreebsd'))
RUNNING_OPENBSD = platform.startswith('openbsd')
RUNNING_MACOSX = (platform == 'darwin')
RUNNING_BSD = RUNNING_FREEBSD or RUNNING_MACOSX or RUNNING_OPENBSD

HAS_PROC = RUNNING_LINUX
HAS_PTRACE = (RUNNING_BSD or RUNNING_LINUX)

