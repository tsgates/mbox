from ptrace.syscall.posix_constants import SYSCALL_ARG_DICT

RLIMIT_RESOURCE = {
     0: "RLIMIT_CPU",
     1: "RLIMIT_FSIZE",
     2: "RLIMIT_DATA",
     3: "RLIMIT_STACK",
     4: "RLIMIT_CORE",
     5: "RLIMIT_RSS",
     6: "RLIMIT_MEMLOCK",
     7: "RLIMIT_NPROC",
     8: "RLIMIT_NOFILE",
     9: "RLIMIT_SBSIZE",
    10: "RLIMIT_VMEM",
}

SIGPROCMASK_HOW = {1:" SIG_BLOCK", 2: "SIG_UNBLOCK", 3: "SIG_SETMASK"}

SYSCALL_ARG_DICT.update({
    "getrlimit": {"resource": RLIMIT_RESOURCE},
    "setrlimit": {"resource": RLIMIT_RESOURCE},
    "sigprocmask": {"how": SIGPROCMASK_HOW},
    "rt_sigprocmask": {"how": SIGPROCMASK_HOW},
})

