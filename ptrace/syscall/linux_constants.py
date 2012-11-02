from ptrace.syscall.posix_constants import SYSCALL_ARG_DICT

SIGSET_SIZE = 64
FD_SETSIZE = 1024

RLIMIT_RESOURCE = {
     0: "RLIMIT_CPU",
     1: "RLIMIT_FSIZE",
     2: "RLIMIT_DATA",
     3: "RLIMIT_STACK",
     4: "RLIMIT_CORE",
     5: "RLIMIT_RSS",
     6: "RLIMIT_NPROC",
     7: "RLIMIT_NOFILE",
     8: "RLIMIT_MEMLOCK",
     9: "RLIMIT_AS",
    10: "RLIMIT_LOCKS",
    11: "RLIMIT_SIGPENDING",
    12: "RLIMIT_MSGQUEUE",
    13: "RLIMIT_NICE",
    14: "RLIMIT_RTPRIO",
    15: "RLIMIT_NLIMITS",
}

SIGPROCMASK_HOW = {0: "SIG_BLOCK", 1: "SIG_UNBLOCK", 2: "SIG_SETMASK"}

SYSCALL_ARG_DICT.update({
    "getrlimit": {"resource": RLIMIT_RESOURCE},
    "setrlimit": {"resource": RLIMIT_RESOURCE},
    "sigprocmask": {"how": SIGPROCMASK_HOW},
    "rt_sigprocmask": {"how": SIGPROCMASK_HOW},
})

