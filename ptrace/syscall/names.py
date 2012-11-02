from ptrace.cpu_info import CPU_64BITS
from ptrace.os_tools import RUNNING_LINUX, RUNNING_FREEBSD
if RUNNING_LINUX:
    if CPU_64BITS:
        from ptrace.syscall.linux_syscall64 import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
    else:
        from ptrace.syscall.linux_syscall32 import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
elif RUNNING_FREEBSD:
    from ptrace.syscall.freebsd_syscall import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
else:
    SYSCALL_NAMES = {}
    SOCKET_SYSCALL_NAMES = set()

