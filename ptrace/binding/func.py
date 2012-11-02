from os import strerror
from ctypes import addressof, c_int
from ptrace import PtraceError
from ptrace.ctypes_errno import get_errno
from ptrace.ctypes_tools import formatAddress
from ptrace.os_tools import RUNNING_LINUX, RUNNING_BSD, RUNNING_OPENBSD
from ptrace.cpu_info import CPU_64BITS, CPU_WORD_SIZE, CPU_POWERPC

if RUNNING_OPENBSD:
    from ptrace.binding.openbsd_struct import (
        reg as ptrace_registers_t,
        fpreg as user_fpregs_struct)

elif RUNNING_BSD:
    from ptrace.binding.freebsd_struct import (
        reg as ptrace_registers_t)

elif RUNNING_LINUX:
    from ptrace.binding.linux_struct import (
        user_regs_struct as ptrace_registers_t,
        user_fpregs_struct, siginfo)
    if not CPU_64BITS:
        from ptrace.binding.linux_struct import user_fpxregs_struct
else:
    raise NotImplementedError("Unknown OS!")
REGISTER_NAMES = tuple( name for name, type in ptrace_registers_t._fields_ )

HAS_PTRACE_SINGLESTEP = True
HAS_PTRACE_EVENTS = False
HAS_PTRACE_IO = False
HAS_PTRACE_SIGINFO = False
HAS_PTRACE_GETREGS = False

pid_t = c_int

# PTRACE_xxx constants from /usr/include/sys/ptrace.h
# (Linux 2.6.21 Ubuntu Feisty i386)
PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSER = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
if HAS_PTRACE_SINGLESTEP:
    PTRACE_SINGLESTEP = 9

if RUNNING_OPENBSD:
    # OpenBSD 4.2 i386
    PTRACE_ATTACH = 9
    PTRACE_DETACH = 10
    HAS_PTRACE_GETREGS = True
    PTRACE_GETREGS = 33
    PTRACE_SETREGS = 34
    PTRACE_GETFPREGS = 35
    PTRACE_SETFPREGS = 36
    HAS_PTRACE_IO = True
    PTRACE_IO = 11
    HAS_PTRACE_SINGLESTEP = True
    PTRACE_SINGLESTEP = 32 # PT_STEP
    #HAS_PTRACE_EVENTS = True
    #PTRACE_SETOPTIONS = 12 # PT_SET_EVENT_MASK
    #PTRACE_GETEVENTMSG = 14 # PT_GET_PROCESS_STATE
elif RUNNING_BSD:
    # FreeBSD 7.0RC1 i386
    PTRACE_ATTACH = 10
    PTRACE_DETACH = 11
    PTRACE_SYSCALL = 22
    if not CPU_POWERPC:
        HAS_PTRACE_GETREGS = True
        PTRACE_GETREGS = 33
    PTRACE_SETREGS = 34
    HAS_PTRACE_IO = True
    PTRACE_IO = 12
else:
    # Linux
    HAS_PTRACE_GETREGS = True
    PTRACE_GETREGS = 12
    PTRACE_SETREGS = 13
    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    PTRACE_SYSCALL = 24
if RUNNING_LINUX:
    PTRACE_GETFPREGS = 14
    PTRACE_SETFPREGS = 15
    if not CPU_64BITS:
        PTRACE_GETFPXREGS = 18
        PTRACE_SETFPXREGS = 19
    HAS_PTRACE_SIGINFO = True
    PTRACE_GETSIGINFO = 0x4202
    PTRACE_SETSIGINFO = 0x4203

    HAS_PTRACE_EVENTS = True
    PTRACE_SETOPTIONS = 0x4200
    PTRACE_GETEVENTMSG = 0x4201

PTRACE_O_TRACESYSGOOD   = 0x00000001
PTRACE_O_TRACEFORK      = 0x00000002
PTRACE_O_TRACEVFORK     = 0x00000004
PTRACE_O_TRACECLONE     = 0x00000008
PTRACE_O_TRACEEXEC      = 0x00000010
PTRACE_O_TRACEVFORKDONE = 0x00000020
PTRACE_O_TRACEEXIT      = 0x00000040

# Wait extended result codes for the above trace options
PTRACE_EVENT_FORK       = 1
PTRACE_EVENT_VFORK      = 2
PTRACE_EVENT_CLONE      = 3
PTRACE_EVENT_EXEC       = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT       = 6

try:
    from cptrace import ptrace as _ptrace
    HAS_CPTRACE = True
except ImportError:
    HAS_CPTRACE = False
    from ctypes import c_long, c_ulong
    from ptrace.ctypes_libc import libc

    # Load ptrace() function from the system C library
    _ptrace = libc.ptrace
    _ptrace.argtypes = (c_ulong, c_ulong, c_ulong, c_ulong)
    _ptrace.restype = c_ulong

def ptrace(command, pid=0, arg1=0, arg2=0, check_errno=False):
    if HAS_CPTRACE:
        try:
            result = _ptrace(command, pid, arg1, arg2)
        except ValueError, errobj:
            message = str(errobj)
            errno = get_errno()
            raise PtraceError(message, errno=errno, pid=pid)
    else:
        result = _ptrace(command, pid, arg1, arg2)
        result_signed = c_long(result).value
        if result_signed == -1:
            errno = get_errno()
            # peek operations may returns -1 with errno=0:
            # it's not an error. For other operations, -1
            # is always an error
            if not(check_errno) or errno:
                message = "ptrace(cmd=%s, pid=%s, %r, %r) error #%s: %s" % (
                    command, pid, arg1, arg2,
                    errno, strerror(errno))
                raise PtraceError(message, errno=errno, pid=pid)
    return result

def ptrace_traceme():
    ptrace(PTRACE_TRACEME)

def ptrace_attach(pid):
    ptrace(PTRACE_ATTACH, pid)

def ptrace_detach(pid, signal=0):
    ptrace(PTRACE_DETACH, pid, 0, signal);

def _peek(command, pid, address):
    if address % CPU_WORD_SIZE:
        raise PtraceError(
            "ptrace can't read a word from an unaligned address (%s)!"
            % formatAddress(address), pid=pid)
    return ptrace(command, pid, address, check_errno=True)

def _poke(command, pid, address, word):
    if address % CPU_WORD_SIZE:
        raise PtraceError(
            "ptrace can't write a word to an unaligned address (%s)!"
            % formatAddress(address), pid=pid)
    ptrace(command, pid, address, word)

def ptrace_peektext(pid, address):
    return _peek(PTRACE_PEEKTEXT, pid, address)

def ptrace_peekdata(pid, address):
    return _peek(PTRACE_PEEKDATA, pid, address)

def ptrace_peekuser(pid, address):
    return _peek(PTRACE_PEEKUSER, pid, address)

def ptrace_poketext(pid, address, word):
    _poke(PTRACE_POKETEXT, pid, address, word)

def ptrace_pokedata(pid, address, word):
    _poke(PTRACE_POKEDATA, pid, address, word)

def ptrace_pokeuser(pid, address, word):
    _poke(PTRACE_POKEUSER, pid, address, word)

def ptrace_kill(pid):
    ptrace(PTRACE_KILL, pid)

if HAS_PTRACE_EVENTS:
    def WPTRACEEVENT(status):
        return status >> 16

    def ptrace_setoptions(pid, options):
        ptrace(PTRACE_SETOPTIONS, pid, 0, options)

    def ptrace_geteventmsg(pid):
        new_pid = pid_t()
        ptrace(PTRACE_GETEVENTMSG, pid, 0, addressof(new_pid))
        return new_pid.value

if RUNNING_LINUX:
    def ptrace_syscall(pid, signum=0):
        ptrace(PTRACE_SYSCALL, pid, 0, signum)

    def ptrace_cont(pid, signum=0):
        ptrace(PTRACE_CONT, pid, 0, signum)

    def ptrace_getsiginfo(pid):
        info = siginfo()
        ptrace(PTRACE_GETSIGINFO, pid, 0, addressof(info))
        return info

    def ptrace_setsiginfo(pid, info):
        ptrace(PTRACE_SETSIGINFO, pid, 0, addressof(info))

    def ptrace_getfpregs(pid):
        fpregs = user_fpregs_struct()
        ptrace(PTRACE_GETFPREGS, pid, 0, addressof(fpregs))
        return fpregs

    def ptrace_setfpregs(pid, fpregs):
        ptrace(PTRACE_SETFPREGS, pid, 0, addressof(fpregs))

    if not CPU_64BITS:
        def ptrace_getfpxregs(pid):
            fpxregs = user_fpxregs_struct()
            ptrace(PTRACE_GETFPXREGS, pid, 0, addressof(fpxregs))
            return fpxregs

        def ptrace_setfpxregs(pid, fpxregs):
            ptrace(PTRACE_SETFPXREGS, pid, 0, addressof(fpxregs))

    if HAS_PTRACE_GETREGS:
        def ptrace_getregs(pid):
            regs = ptrace_registers_t()
            ptrace(PTRACE_GETREGS, pid, 0, addressof(regs))
            return regs

    def ptrace_setregs(pid, regs):
        ptrace(PTRACE_SETREGS, pid, 0, addressof(regs))

    if HAS_PTRACE_SINGLESTEP:
        def ptrace_singlestep(pid):
            ptrace(PTRACE_SINGLESTEP, pid)

else:
    def ptrace_syscall(pid, signum=0):
        ptrace(PTRACE_SYSCALL, pid, 1, signum)

    def ptrace_cont(pid, signum=0):
        ptrace(PTRACE_CONT, pid, 1, signum)

    if HAS_PTRACE_GETREGS:
        def ptrace_getregs(pid):
            regs = ptrace_registers_t()
            ptrace(PTRACE_GETREGS, pid, addressof(regs))
            return regs

    def ptrace_setregs(pid, regs):
        ptrace(PTRACE_SETREGS, pid, addressof(regs))

    if HAS_PTRACE_SINGLESTEP:
        def ptrace_singlestep(pid):
            ptrace(PTRACE_SINGLESTEP, pid, 1)

if HAS_PTRACE_IO:
    def ptrace_io(pid, io_desc):
        ptrace(PTRACE_IO, pid, addressof(io_desc))

