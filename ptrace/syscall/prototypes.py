# From Linux kernel source code
#    include/linux/syscalls.h
#    arch/i386/kernel/syscall_table.S
#    arch/um/include/sysdep-i386/syscalls.h
#    arch/um/sys-i386/sys_call_table.S

ALIASES = {
    "mmap": ("mmap2",),
    "break": ("brk",),
    "exit": ("exit_group",),
    "fcntl": ("fcntl64",),
}

# Name of arguments containing a filename or a path
FILENAME_ARGUMENTS = set(("filename", "pathname"))

SYSCALL_PROTOTYPES = {
    "read": ("ssize_t", (
            ("unsigned int", "fd"),
            ("char*", "buf"),
            ("size_t", "count"),
        )),
    "write": ("ssize_t", (
            ("int", "fd"),
            ("const char*", "buf"),
            ("size_t", "count"),
        )),
    "open": ("long", (
            ("const char*", "filename"),
            ("int", "mode"),
        )),
    "readlink": ("long", (
            ("const char*", "pathname"),
            ("char*", "buf"),
            ("int", "bufsize"),
        )),
    "close": ("long", (
            ("unsigned int", "fd"),
        )),
    "set_tid_address": ("long", (
            ("int*", "tidptr"),
        )),
    "set_robust_list": ("long", (
            ("struct robust_list_head*", "head"),
            ("size_t", "len_ptr"),
        )),
    "fcntl": ("long", (
            ("unsigned int", "fd"),
            ("unsigned int", "cmd"),
            ("unsigned int", "arg"),
        )),
    "stat": ("long", (
            ("const char*", "filename"),
            ("struct oldstat*", "statbuf"),
        )),
    "stat64": ("long", (
            ("const char*", "filename"),
            ("struct stat64*", "statbuf"),
        )),
    "lstat": ("long", (
            ("const char*", "filename"),
            ("struct oldstat*", "statbuf"),
        )),
    "lstat64": ("long", (
            ("const char*", "filename"),
            ("struct stat64*", "statbuf"),
        )),
    "fstat": ("long", (
            ("unsigned int", "fd"),
            ("struct oldstat*", "statbuf"),
        )),
    "fstat64": ("long", (
            ("unsigned long", "fd"),
            ("struct stat64*", "buf"),
        )),
    "fstatat64": ("long", (
            ("unsigned long", "dirfd"),
            ("const char*", "filename"),
            ("struct stat64*", "statbuf"),
            ("int", "flags"),
        )),
    "statfs": ("long", (
            ("const char*", "pathname"),
            ("struct statfs*", "buf"),
        )),
    "fstatfs": ("long", (
            ("int", "fs"),
            ("struct statfs*", "buf"),
        )),
    "access": ("long", (
            ("char*", "filename"),
            ("int", "mode"),
        )),
    "lseek": ("long", (
            ("unsigned int", "fd"),
            ("unsigned long", "offset"),
            ("loff_t*", "result"),
            ("unsigned int", "origin"),
        )),
    "llseek": ("long", (
            ("unsigned int", "fd"),
            ("unsigned long", "offset_high"),
            ("unsigned long", "offset_low"),
            ("loff_t*", "result"),
            ("unsigned int", "origin"),
        )),
    "break": ("void*", (
            ("void*", "brk"),
        )),
    "sigprocmask": ("int", (
            ("int", "how"),
            ("const old_sigset_t*", "set"),
            ("old_sigset_t*", "ofset"),
        )),
    "rt_sigprocmask": ("int", (
            ("int", "how"),
            ("const sigset_t*", "set"),
            ("sigset_t*", "ofset"),
            ("size_t", "sigsetsize"),
        )),
    "sigaction": ("long", (
            ("int", "signum"),
            ("const struct oldsigaction*", "act"),
            ("struct oldsigaction*", "oldact"),
        )),
    "rt_sigaction": ("long", (
            # FIXME: Check parameters!
            ("int", "signum"),
            ("const struct sigaction*", "act"),
            ("struct sigaction*", "oldact"),
            ("int", "sigsetsize"),
        )),
    "select": ("long", (
            ("int", "n"),
            ("fd_set*", "inp"),
            ("fd_set*", "outp"),
            ("fd_set*", "exp"),
            ("struct timeval*", "timeout"),
        )),
    "poll": ("long", (
            ("struct pollfd*", "ufds"),
            ("int", "nfds"),
            ("long", "timeout"),
        )),
    "gettimeofday": ("long", (
            ("struct timeval*", "tv"),
            ("struct timezone*", "tz"),
        )),
    "settimeofday": ("long", (
            ("struct timeval*", "tv"),
            ("struct timezone*", "tz"),
        )),
    "socketcall": ("long", (
            ("int", "call"),
            ("unsigned long*", "args"),
        )),
    "clock_gettime": ("long", (
            ("clockid_t", "which_clock"),
            ("struct timespec*", "tp"),
        )),
    "clock_getres": ("long", (
            ("clockid_t", "which_clock"),
            ("struct timespec*", "tp"),
        )),
    "time": ("time_t", (
            ("time_t*", "tloc"),
        )),
    "stime": ("long", (
            ("time_t*", "tptr"),
        )),
    "munmap": ("long", (
            ("void*", "addr"),
            ("size_t", "length"),
        )),
    "mmap": ("void*", (
            ("void*", "start"),
            ("unsigned long", "length"),
            ("unsigned long", "prot"),
            ("long", "flags"),
            ("long", "fd"),
            ("unsigned long", "offset"),
        )),
    "madvise": ("long", (
            ("unsigned long", "start"),
            ("size_t", "length"),
            ("int", "behaviour"),
        )),
    "exit": ("void", (
            ("int", "error_code"),
        )),
    "futex": ("long", (
            ("u32*", "uaddr"),
            ("int", "op"),
            ("u32", "val"),
            ("struct timespec*", "utime"),
            ("u32*", "uaddr2"),
            ("u32", "val3"),
        )),
    "ioctl": ("long", (
            ("unsigned int", "fd"),
            ("unsigend int", "cmd"),
            ("void*", "arg"),
        )),
    "getrusage": ("long", (
            ("int", "who"),
            ("struct rusage*", "usage"),
        )),
    "times": ("clock_t", (
            ("struct tms*", "tbuf"),
        )),
    "mprotect": ("long", (
            ("void*", "start"),
            ("size_t", "len"),
            ("unsigned long", "prot"),
        )),
    "getrlimit": ("int", (
            ("unsigned int", "resource"),
            ("struct rlimit*", "rlim"),
        )),
    "setrlimit": ("int", (
            ("unsigned int", "resource"),
            ("struct rlimit*", "rlim"),
        )),

    "getuid": ("uid_t", tuple()),
    "geteuid": ("uid_t", tuple()),
    "getuid16": ("uid16_t", tuple()),
    "geteuid16": ("uid16_t", tuple()),
    "issetugid": ("long", tuple()),

    "getgid": ("gid_t", tuple()),
    "getegid": ("gid_t", tuple()),
    "getgid16": ("gid16_t", tuple()),
    "getegid16": ("gid16_t", tuple()),

    "getpid": ("pid_t", tuple()),
    "getppid": ("pid_t", tuple()),

    "setuid": ("long", (("uid_t", "uid"),)),
    "setreuid": ("long", (("uid_t", "uid"),)),
    "setfsuid": ("long", (("uid_t", "uid"),)),

    "setgid": ("long", (("gid_t", "gid"),)),
    "setregid": ("long", (("gid_t", "gid"),)),
    "setfsgid": ("long", (("gid_t", "gid"),)),

    "getsid": ("long", (("pid_t", "pid"),)),
    "setsid": ("long", tuple()),

    "pipe": ("int", (
            ("int[2]", "filedes"),
        )),
    "wait4": ("pid_t", (
            ("pid_t", "pid"),
            ("int*", "status"),
            ("int", "options"),
            ("struct rusage*", "rusage"),
        )),
    "waitpid": ("pid_t", (
            ("pid_t", "pid"),
            ("int*", "status"),
            ("int", "options"),
        )),
    "set_thread_area": ("long", (
            ("struct user_desc*", "u_info"),
        )),
    "oldolduname": ("long", (
            ("struct oldold_utsname*", "name"),
        )),
    "olduname": ("long", (
            ("struct old_utsname*", "name"),
        )),
    "uname": ("long", (
            ("struct new_utsname*", "name"),
        )),
    "clone": ("long", (
            ("int", "flags"),
            ("void*", "child_stack"),
            ("void*", "parent_tidptr"),
            ("struct user_desc*", "newtls"),
            ("void*", "child_tidptr"),
        )),
    "__getcwd": ("long", (
            ("char*", "pathname"),
            ("size_t", "size"),
        )),
    "dup2": ("long", (
            ("int", "fd"),
            ("int", "fd2"),
        )),
    "fork": ("uid_t", tuple()),
    "execve": ("long", (
            ("const char*", "filename"),
            ("const char**", "argv"),
            ("const char**", "envp"),
        )),
    "readv": ("ssize_t", (
            ("int", "fd"),
            ("const iovec*", "vector"),
            ("int", "count"),
        )),
    "writev": ("ssize_t", (
            ("int", "fd"),
            ("const iovec*", "vector"),
            ("int", "count"),
        )),
    "openat": ("long", (
            ("int", "dirfd"),
            ("const char*", "pathname"),
            ("int", "flags"),
            ("int", "mode"),
        )),
    "getdents": ("long", (
            ("int", "fd"),
            ("struct dirent*", "dirp"),
            ("unsigned int", "count"),
        )),
    "getdents64": ("long", (
            ("int", "fd"),
            ("struct dirent64*", "dirp"),
            ("unsigned int", "count"),
        )),
    "dup": ("long", (
            ("int", "fd"),
        )),
    "dup2": ("long", (
            ("int", "oldfd"),
            ("int", "newfd"),
        )),
    "fchdir": ("long", (
            ("int", "fd"),
        )),
    "getdirentries": ("long", (
            ("int", "fd"),
            ("void*", "buf"),
            ("int", "nbytes"),
            ("long*", "basep"),
        )),
    "unlink": ("long", (
            ("const char*", "pathname"),
        )),
    "kill" : ("long", (
            ("int", "pid"),
            ("int", "signum"),
        )),
    "modify_ldt" : ("long", (
            ("int", "func"),
            ("void*", "ptr"),
            ("unsigned long", "bytecount"),
        )),
    "ipc" : ("long", (
            ("unsigned int", "call"),
            ("int", "first"),
            ("unsigned long", "second"),
            ("long", "third"),
            ("void*", "ptr"),
            ("long", "fifth"),
        )),
    "nanosleep" : ("long", (
            ("struct timespec*", "rqtp"),
            ("struct timespec*", "rmtp"),
        )),
    "restart_syscall" : ("long", tuple()),
    "getsockname" : ("long", (
            ("int", "fd"),
            ("struct sockaddr*", "name"),
            ("socklen_t*", "namelen"),
        )),
    "getpeername" : ("long", (
            ("int", "fd"),
            ("struct sockaddr*", "name"),
            ("socklen_t*", "namelen"),
        )),
    "getsockopt" : ("long", (
            ("int", "fd"),
            ("int", "level"),
            ("int", "optname"),
            ("void*", "optval"),
            ("socklen_t*", "optlen"),
        )),
    "setsockopt" : ("long", (
            ("int", "fd"),
            ("int", "level"),
            ("int", "optname"),
            ("void*", "optval"),
            ("socklen_t*", "optlen"),
        )),
    "bind" : ("long", (
            ("int", "fd"),
            ("const struct sockaddr*", "addr"),
            ("socklen_t", "addrlen"),
        )),
    "connect" : ("long", (
            ("int", "fd"),
            ("const struct sockaddr*", "addr"),
            ("socklen_t", "addrlen"),
        )),
    "socket" : ("long", (
            ("int", "domain"),
            ("int", "type"),
            ("int", "protocol"),
        )),
    "alarm" : ("long", (
            ("unsigned int", "seconds"),
        )),
    "recv": ("ssize_t", (
            ("int", "sockfd"),
            ("void*", "buf"),
            ("size_t", "len"),
            ("int", "flags"),
        )),
    "recvfrom": ("ssize_t", (
            ("int", "sockfd"),
            ("void*", "buf"),
            ("size_t", "len"),
            ("int", "flags"),
            ("struct sockaddr*", "src_addr"),
            ("socklen_t", "addrlen"),
        )),
    "recvmsg": ("ssize_t", (
            ("int", "sockfd"),
            ("struct msghdr*", "msg"),
            ("int", "flags"),
        )),
    "send": ("ssize_t", (
            ("int", "sockfd"),
            ("const void*", "buf"),
            ("size_t", "len"),
            ("int", "flags"),
        )),
    "sendto": ("ssize_t", (
            ("int", "sockfd"),
            ("const void*", "buf"),
            ("size_t", "len"),
            ("int", "flags"),
            ("const struct sockaddr*", "dest_addr"),
            ("socklen_t", "addrlen"),
        )),
    "sendmsg": ("ssize_t", (
            ("int", "sockfd"),
            ("const struct msghdr*", "buf"),
            ("int", "flags"),
        )),
    "listen": ("int", (
            ("int", "fd"),
            ("int", "backlog"),
        )),
    "accept": ("int", (
            ("int", "fd"),
            ("struct sockaddr*", "addr"),
            ("socklen_t*", "addrlen"),
        )),
    "socketpair": ("int", (
            ("int", "family"),
            ("int", "type"),
            ("int", "protocol"),
            ("int*", "sockvec"),
        )),
    "shutdown": ("int", (
            ("int", "fd"),
            ("int", "how"),
        )),
}

for orig, copies in ALIASES.iteritems():
    orig = SYSCALL_PROTOTYPES[orig]
    for copy in copies:
        SYSCALL_PROTOTYPES[copy] = orig

