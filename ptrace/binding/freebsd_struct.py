from ctypes import Structure, c_int, c_uint, c_ulong, c_void_p

PIOD_READ_D = 1
PIOD_WRITE_D = 2
PIOD_READ_I = 3
PIOD_WRITE_I = 4

size_t = c_ulong

# /usr/include/machine/reg.h
class reg(Structure):
    _fields_ = (
        ("fs", c_uint),
        ("es", c_uint),
        ("ds", c_uint),
        ("edi", c_uint),
        ("esi", c_uint),
        ("ebp", c_uint),
        ("isp", c_uint),
        ("ebx", c_uint),
        ("edx", c_uint),
        ("ecx", c_uint),
        ("eax", c_uint),
        ("trapno", c_uint),
        ("err", c_uint),
        ("eip", c_uint),
        ("cs", c_uint),
        ("eflags", c_uint),
        ("esp", c_uint),
        ("ss", c_uint),
        ("gs", c_uint),
    )

class ptrace_io_desc(Structure):
    _fields_ = (
        ("piod_op", c_int),
        ("piod_offs", c_void_p),
        ("piod_addr", c_void_p),
        ("piod_len", size_t),
    )

