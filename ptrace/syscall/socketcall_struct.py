from ctypes import Structure, Union, c_char, c_ushort, c_ubyte, c_uint16, c_uint32
from ptrace.os_tools import RUNNING_BSD, RUNNING_LINUX
from socket import inet_ntoa
from struct import pack
from ptrace.ctypes_tools import ntoh_uint, ntoh_ushort

def ip_int2str(ip):
    """
    Convert an IP address (as an interger) to a string.

    >>> ip_int2str(0x7f000001)
    '127.0.0.1'
    """
    ip_bytes = pack("!I", ip)
    return inet_ntoa(ip_bytes)

if RUNNING_BSD:
    sa_family_t = c_ubyte
else:
    sa_family_t = c_ushort

class sockaddr(Structure):
    if RUNNING_BSD:
        _fields_ = (
            ("len", c_ubyte),
            ("family", sa_family_t),
        )
    else:
        _fields_ = (
            ("family", sa_family_t),
        )

class in_addr(Structure):
    _fields_ = (
        ("s_addr", c_uint32),
    )

    def __repr__(self):
        ip = ntoh_uint(self.s_addr)
        return ip_int2str(ip)

class in6_addr(Union):
    _fields_ = (
        ("addr8", c_ubyte * 16),
        ("addr16", c_uint16 * 8),
        ("addr32", c_uint32 * 4),
    )

    def __repr__(self):
        text = ':'.join(("%04x" % ntoh_ushort(part)) for part in self.addr16)
        return "<in6_addrr %s>" % text

# INET socket
class sockaddr_in(Structure):
    if RUNNING_BSD:
        _fields_ = (
            ("sin_len", c_ubyte),
            ("sin_family", sa_family_t),
            ("sin_port", c_uint16),
            ("sin_addr", in_addr),
        )
    else:
        _fields_ = (
            ("sin_family", sa_family_t),
            ("sin_port", c_uint16),
            ("sin_addr", in_addr),
        )

class sockaddr_in6(Structure):
    if RUNNING_BSD:
        _fields_ = (
            ("sin6_len", c_ubyte),
            ("sin6_family", sa_family_t),
            ("sin6_port", c_uint16),
            ("sin6_flowinfo", c_uint32),
            ("sin6_addr", in6_addr),
        )
    else:
        _fields_ = (
            ("sin6_family", sa_family_t),
            ("sin6_port", c_uint16),
            ("sin6_flowinfo", c_uint32),
            ("sin6_addr", in6_addr),
            ("sin6_scope_ip", c_uint32),
        )

# UNIX socket
class sockaddr_un(Structure):
    _fields_ = (
        ("sun_family", sa_family_t),
        ("sun_path", c_char*108),
    )

# Netlink socket
if RUNNING_LINUX:
    class sockaddr_nl(Structure):
        _fields_ = (
            ("nl_family", sa_family_t),
            ("nl_pad", c_ushort),
            ("nl_pid", c_uint32),
            ("nl_groups", c_uint32),
        )

