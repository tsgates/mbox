from ctypes import (Structure, Union, sizeof,
    c_char, c_ushort, c_int, c_uint, c_ulong, c_void_p,
    c_uint16, c_uint32, c_uint64)
from ptrace.cpu_info import CPU_64BITS, CPU_PPC32

pid_t = c_int
uid_t = c_ushort
clock_t = c_uint

# From /usr/include/asm-i386/user.h
class user_regs_struct(Structure):
    if CPU_PPC32:
        _fields_ = (
            ("gpr0", c_ulong),
            ("gpr1", c_ulong),
            ("gpr2", c_ulong),
            ("gpr3", c_ulong),
            ("gpr4", c_ulong),
            ("gpr5", c_ulong),
            ("gpr6", c_ulong),
            ("gpr7", c_ulong),
            ("gpr8", c_ulong),
            ("gpr9", c_ulong),
            ("gpr10", c_ulong),
            ("gpr11", c_ulong),
            ("gpr12", c_ulong),
            ("gpr13", c_ulong),
            ("gpr14", c_ulong),
            ("gpr15", c_ulong),
            ("gpr16", c_ulong),
            ("gpr17", c_ulong),
            ("gpr18", c_ulong),
            ("gpr19", c_ulong),
            ("gpr20", c_ulong),
            ("gpr21", c_ulong),
            ("gpr22", c_ulong),
            ("gpr23", c_ulong),
            ("gpr24", c_ulong),
            ("gpr25", c_ulong),
            ("gpr26", c_ulong),
            ("gpr27", c_ulong),
            ("gpr28", c_ulong),
            ("gpr29", c_ulong),
            ("gpr30", c_ulong),
            ("gpr31", c_ulong),
            ("nip", c_ulong),
            ("msr", c_ulong),
            ("orig_gpr3", c_ulong),
            ("ctr", c_ulong),
            ("link", c_ulong),
            ("xer", c_ulong),
            ("ccr", c_ulong),
            ("mq", c_ulong), # FIXME: ppc64 => softe
            ("trap", c_ulong),
            ("dar", c_ulong),
            ("dsisr", c_ulong),
            ("result", c_ulong),
        )
    elif CPU_64BITS:
        _fields_ = (
            ("r15", c_ulong),
            ("r14", c_ulong),
            ("r13", c_ulong),
            ("r12", c_ulong),
            ("rbp", c_ulong),
            ("rbx", c_ulong),
            ("r11", c_ulong),
            ("r10", c_ulong),
            ("r9", c_ulong),
            ("r8", c_ulong),
            ("rax", c_ulong),
            ("rcx", c_ulong),
            ("rdx", c_ulong),
            ("rsi", c_ulong),
            ("rdi", c_ulong),
            ("orig_rax", c_ulong),
            ("rip", c_ulong),
            ("cs", c_ulong),
            ("eflags", c_ulong),
            ("rsp", c_ulong),
            ("ss", c_ulong),
            ("fs_base", c_ulong),
            ("gs_base", c_ulong),
            ("ds", c_ulong),
            ("es", c_ulong),
            ("fs", c_ulong),
            ("gs", c_ulong)
            )
    else:
        _fields_ = (
            ("ebx", c_ulong),
            ("ecx", c_ulong),
            ("edx", c_ulong),
            ("esi", c_ulong),
            ("edi", c_ulong),
            ("ebp", c_ulong),
            ("eax", c_ulong),
            ("ds", c_ushort),
            ("__ds", c_ushort),
            ("es", c_ushort),
            ("__es", c_ushort),
            ("fs", c_ushort),
            ("__fs", c_ushort),
            ("gs", c_ushort),
            ("__gs", c_ushort),
            ("orig_eax", c_ulong),
            ("eip", c_ulong),
            ("cs", c_ushort),
            ("__cs", c_ushort),
            ("eflags", c_ulong),
            ("esp", c_ulong),
            ("ss", c_ushort),
            ("__ss", c_ushort),
            )

class user_fpregs_struct(Structure):
    if CPU_64BITS:
        _fields_ = (
            ("cwd", c_uint16),
            ("swd", c_uint16),
            ("ftw", c_uint16),
            ("fop", c_uint16),
            ("rip", c_uint64),
            ("rdp", c_uint64),
            ("mxcsr", c_uint32),
            ("mxcr_mask", c_uint32),
            ("st_space", c_uint32 * 32),
            ("xmm_space", c_uint32 * 64),
            ("padding", c_uint32 * 24)
            )
    else:
        _fields_ = (
            ("cwd", c_ulong),
            ("swd", c_ulong),
            ("twd", c_ulong),
            ("fip", c_ulong),
            ("fcs", c_ulong),
            ("foo", c_ulong),
            ("fos", c_ulong),
            ("st_space", c_ulong * 20)
            )

if not CPU_64BITS:
    class user_fpxregs_struct(Structure):
        _fields_ = (
            ("cwd", c_ushort),
            ("swd", c_ushort),
            ("twd", c_ushort),
            ("fop", c_ushort),
            ("fip", c_ulong),
            ("fcs", c_ulong),
            ("foo", c_ulong),
            ("fos", c_ulong),
            ("mxcsr", c_ulong),
            ("reserved", c_ulong),
            ("st_space", c_ulong * 32),
            ("xmm_space", c_ulong * 32),
            ("padding", c_ulong * 56)
        )

# From /usr/include/asm-generic/siginfo.h
class _sifields_sigfault_t(Union):
    _fields_ = (
        ("_addr", c_void_p),
    )

class _sifields_sigchld_t(Structure):
    _fields_ = (
        ("pid", pid_t),
        ("uid", uid_t),
        ("status", c_int),
        ("utime", clock_t),
        ("stime", clock_t),
    )

class _sifields_t(Union):
    _fields_ = (
       ("pad", c_char * (128 - 3 * sizeof(c_int))),
       ("_sigchld", _sifields_sigchld_t),
       ("_sigfault", _sifields_sigfault_t),
#        ("_kill", _sifields_kill_t),
#        ("_timer", _sifields_timer_t),
#        ("_rt", _sifields_rt_t),
#        ("_sigpoll", _sifields_sigpoll_t),
    )

class siginfo(Structure):
    _fields_ = (
        ("si_signo", c_int),
        ("si_errno", c_int),
        ("si_code", c_int),
        ("_sifields", _sifields_t)
        )
    _anonymous_ = ("_sifields",)

