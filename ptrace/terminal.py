"""
Terminal functions.
"""

from termios import tcgetattr, tcsetattr, ECHO, TCSADRAIN, TIOCGWINSZ
from sys import stdin, stdout
from fcntl import ioctl
from struct import unpack

TERMIO_LFLAGS = 3

def _terminalSize():
    fd = stdout.fileno()
    size = ioctl(fd, TIOCGWINSZ, '1234')
    height, width = unpack('hh', size)
    return (width, height)

def terminalWidth():
    """
    Get the terminal width in characters.
    """
    return _terminalSize()[0]

def enableEchoMode():
    """
    Enable echo mode in the terminal. Return True if the echo mode is set
    correctly, or False if the mode was already set.
    """
    fd = stdin.fileno()
    state = tcgetattr(fd)
    if state[TERMIO_LFLAGS] & ECHO:
        return False
    state[TERMIO_LFLAGS] = state[TERMIO_LFLAGS] | ECHO
    tcsetattr(fd, TCSADRAIN, state)
    return True


