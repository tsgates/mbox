from ctypes import (Structure,
    c_char, c_short, c_int, c_uint, c_long,  c_ulong)

time_t = c_long
suseconds_t = c_long
rlim_t = c_long

class timeval(Structure):
    _fields_ = (
        ("tv_sec", time_t),
        ("tv_usec", suseconds_t),
    )

class timespec(Structure):
    _fields_ = (
        ("tv_sec", time_t),
        ("tv_nsec", c_long),
    )

class pollfd(Structure):
    _fields_ = (
        ("fd", c_int),
        ("events", c_short),
        ("revents", c_short),
    )

class rlimit(Structure):
    _fields_ = (
        ("rlim_cur", rlim_t),
        ("rlim_max", rlim_t),
    )

class new_utsname(Structure):
    _fields_ = (
        ("sysname", c_char*65),
        ("nodename", c_char*65),
        ("release", c_char*65),
        ("version", c_char*65),
        ("machine", c_char*65),
        ("domainname", c_char*65),
    )

# Arch depend
class user_desc(Structure):
    _fields_ = (
        ("entry_number", c_uint),
        ("base_addr", c_ulong),
        ("limit", c_uint),
        ("_bits_", c_char),
#	unsigned int  seg_32bit:1;
#	unsigned int  contents:2;
#	unsigned int  read_exec_only:1;
#	unsigned int  limit_in_pages:1;
#	unsigned int  seg_not_present:1;
#	unsigned int  useable:1;
    )


