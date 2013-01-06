{ 3,    TD,     sys_read,               NULL, "read"				},	/* 0 */
{ 3,    TD,     sys_write,              NULL, "write"				},	/* 1 */
{ 3,    TD|TF,  sys_open,               NULL, "open"				},	/* 2 */
{ 1,    TD,     sys_close,              NULL, "close"				},	/* 3 */
{ 2,    TF,     sys_stat,               NULL, "stat"				},	/* 4 */
{ 2,    TD,     sys_fstat,              NULL, "fstat"				},	/* 5 */
{ 2,    TF,     sys_lstat,              NULL, "lstat"				},	/* 6 */
{ 3,    TD,     sys_poll,               NULL, "poll"				},	/* 7 */
{ 3,    TD,     sys_lseek,              NULL, "lseek"				},	/* 8 */
{ 6,    TD,     sys_mmap,               NULL, "mmap"				},	/* 9 */
{ 3,    0,      sys_mprotect,           NULL, "mprotect"			},	/* 10 */
{ 2,    0,      sys_munmap,             NULL, "munmap"				},	/* 11 */
{ 1,    0,      sys_brk,                NULL, "brk"				},	/* 12 */
{},											/* 13 */
{ 4,    TS,     sys_rt_sigprocmask,     NULL, "rt_sigprocmask"			},	/* 14 */
{},											/* 15 */
{},											/* 16 */
{ 5,    TD,     sys_pread,              NULL, "pread"				},	/* 17 */
{ 5,    TD,     sys_pwrite,             NULL, "pwrite"				},	/* 18 */
{},											/* 19 */
{},											/* 20 */
{ 2,    TF,     sys_access,             NULL, "access"				},	/* 21 */
{ 1,    TD,     sys_pipe,               NULL, "pipe"				},	/* 22 */
{ 5,    TD,     sys_select,             NULL, "select"				},	/* 23 */
{ 0,    0,      sys_sched_yield,        NULL, "sched_yield"			},	/* 24 */
{ 5,    0,      sys_mremap,             NULL, "mremap"				},	/* 25 */
{ 3,    0,      sys_msync,              NULL, "msync"				},	/* 26 */
{ 3,    0,      sys_mincore,            NULL, "mincore"				},	/* 27 */
{ 3,    0,      sys_madvise,            NULL, "madvise"				},	/* 28 */
{ 4,    TI,     sys_shmget,             NULL, "shmget"				},	/* 29 */
{ 4,    TI,     sys_shmat,              NULL, "shmat"				},	/* 30 */
{ 4,    TI,     sys_shmctl,             NULL, "shmctl"				},	/* 31 */
{ 1,    TD,     sys_dup,                NULL, "dup"				},	/* 32 */
{ 2,    TD,     sys_dup2,               NULL, "dup2"				},	/* 33 */
{ 0,    TS,     sys_pause,              NULL, "pause"				},	/* 34 */
{ 2,    0,      sys_nanosleep,          NULL, "nanosleep"			},	/* 35 */
{ 2,    0,      sys_getitimer,          NULL, "getitimer"			},	/* 36 */
{ 1,    0,      sys_alarm,              NULL, "alarm"				},	/* 37 */
{ 3,    0,      sys_setitimer,          NULL, "setitimer"			},	/* 38 */
{ 0,    0,      sys_getpid,             NULL, "getpid"				},	/* 39 */
{ 4,    TD|TN,  sys_sendfile,           NULL, "sendfile"			},	/* 40 */
{ 3,    TN,     sys_socket,             NULL, "socket"				},	/* 41 */
{ 3,    TN,     sys_connect,            NULL, "connect"				},	/* 42 */
{ 3,    TN,     sys_accept,             NULL, "accept"				},	/* 43 */
{ 6,    TN,     sys_sendto,             NULL, "sendto"				},	/* 44 */
{},											/* 45 */
{},											/* 46 */
{},											/* 47 */
{ 2,    TN,     sys_shutdown,           NULL, "shutdown"			},	/* 48 */
{ 3,    TN,     sys_bind,               NULL, "bind"				},	/* 49 */
{ 2,    TN,     sys_listen,             NULL, "listen"				},	/* 50 */
{ 3,    TN,     sys_getsockname,        NULL, "getsockname"			},	/* 51 */
{ 3,    TN,     sys_getpeername,        NULL, "getpeername"			},	/* 52 */
{ 4,    TN,     sys_socketpair,         NULL, "socketpair"			},	/* 53 */
{ 5,    TN,     sys_setsockopt,         NULL, "setsockopt"			},	/* 54 */
{ 5,    TN,     sys_getsockopt,         NULL, "getsockopt"			},	/* 55 */
{ 5,    TP,     sys_clone,              NULL, "clone"				},	/* 56 */
{ 0,    TP,     sys_fork,               NULL, "fork"				},	/* 57 */
{ 0,    TP,     sys_vfork,              NULL, "vfork"				},	/* 58 */
{},											/* 47 */
        { 1,    TP,     sys_exit,               NULL, "_exit"			},	/* 60 */
{ 4,    TP,     sys_wait4,              NULL, "wait4"				},	/* 61 */
{ 2,    TS,     sys_kill,               NULL, "kill"				},	/* 62 */
{ 1,    0,      sys_uname,              NULL, "uname"				},	/* 63 */
{ 4,    TI,     sys_semget,             NULL, "semget"				},	/* 64 */
{ 4,    TI,     sys_semop,              NULL, "semop"				},	/* 65 */
{ 4,    TI,     sys_semctl,             NULL, "semctl"				},	/* 66 */
{ 4,    TI,     sys_shmdt,              NULL, "shmdt"				},	/* 67 */
{ 4,    TI,     sys_msgget,             NULL, "msgget"				},	/* 68 */
{ 4,    TI,     sys_msgsnd,             NULL, "msgsnd"				},	/* 69 */
{ 5,    TI,     sys_msgrcv,             NULL, "msgrcv"				},	/* 70 */
{ 3,    TI,     sys_msgctl,             NULL, "msgctl"				},	/* 71 */
{ 3,    TD,     sys_fcntl,              NULL, "fcntl"				},	/* 72 */
{ 2,    TD,     sys_flock,              NULL, "flock"				},	/* 73 */
{ 1,    TD,     sys_fsync,              NULL, "fsync"				},	/* 74 */
{ 1,    TD,     sys_fdatasync,          NULL, "fdatasync"			},	/* 75 */
{ 2,    TF,     sys_truncate,           NULL, "truncate"			},	/* 76 */
{ 2,    TD,     sys_ftruncate,          NULL, "ftruncate"			},	/* 77 */
{},											/* 78 */
        { 2,    TF,     sys_getcwd,             NULL, "getcwd"			},	/* 79 */
{ 1,    TF,     sys_chdir,              NULL, "chdir"				},	/* 80 */
{ 1,    TD,     sys_fchdir,             NULL, "fchdir"				},	/* 81 */
{ 2,    TF,     sys_rename,             NULL, "rename"				},	/* 82 */
{ 2,    TF,     sys_mkdir,              NULL, "mkdir"				},	/* 83 */
{ 1,    TF,     sys_rmdir,              NULL, "rmdir"				},	/* 84 */
{ 2,    TD|TF,  sys_creat,              NULL, "creat"				},	/* 85 */
{ 2,    TF,     sys_link,               NULL, "link"				},	/* 86 */
{ 1,    TF,     sys_unlink,             NULL, "unlink"				},	/* 87 */
{ 2,    TF,     sys_symlink,            NULL, "symlink"				},	/* 88 */
{ 3,    TF,     sys_readlink,           NULL, "readlink"			},	/* 89 */
{ 2,    TF,     sys_chmod,              NULL, "chmod"				},	/* 90 */
{ 2,    TD,     sys_fchmod,             NULL, "fchmod"				},	/* 91 */
{ 3,    TF,     sys_chown,              NULL, "chown"				},	/* 92 */
{ 3,    TD,     sys_fchown,             NULL, "fchown"				},	/* 93 */
{ 3,    TF,     sys_chown,              NULL, "lchown"				},	/* 94 */
{ 1,    0,      sys_umask,              NULL, "umask"				},	/* 95 */
{ 2,    0,      sys_gettimeofday,       NULL, "gettimeofday"			},	/* 96 */
{ 2,    0,      sys_getrlimit,          NULL, "getrlimit"			},	/* 97 */
{ 2,    0,      sys_getrusage,          NULL, "getrusage"			},	/* 98 */
{ 1,    0,      sys_sysinfo,            NULL, "sysinfo"				},	/* 99 */
{ 1,    0,      sys_times,              NULL, "times"				},	/* 100 */
{},											/* 101 */
{ 0,    NF,     sys_getuid,             NULL, "getuid"				},	/* 102 */
{ 3,    0,      sys_syslog,             NULL, "syslog"				},	/* 103 */
{ 0,    NF,     sys_getgid,             NULL, "getgid"				},	/* 104 */
{ 1,    0,      sys_setuid,             NULL, "setuid"				},	/* 105 */
{ 1,    0,      sys_setgid,             NULL, "setgid"				},	/* 106 */
{ 0,    NF,     sys_geteuid,            NULL, "geteuid"				},	/* 107 */
{ 0,    NF,     sys_getegid,            NULL, "getegid"				},	/* 108 */
{ 2,    0,      sys_setpgid,            NULL, "setpgid"				},	/* 109 */
{ 0,    0,      sys_getppid,            NULL, "getppid"				},	/* 110 */
{ 0,    0,      sys_getpgrp,            NULL, "getpgrp"				},	/* 111 */
{ 0,    0,      sys_setsid,             NULL, "setsid"				},	/* 112 */
{ 2,    0,      sys_setreuid,           NULL, "setreuid"			},	/* 113 */
{ 2,    0,      sys_setregid,           NULL, "setregid"			},	/* 114 */
{ 2,    0,      sys_getgroups,          NULL, "getgroups"			},	/* 115 */
{ 2,    0,      sys_setgroups,          NULL, "setgroups"			},	/* 116 */
{ 3,    0,      sys_setresuid,          NULL, "setresuid"			},	/* 117 */
{ 3,    0,      sys_getresuid,          NULL, "getresuid"			},	/* 118 */
{ 3,    0,      sys_setresgid,          NULL, "setresgid"			},	/* 119 */
{ 3,    0,      sys_getresgid,          NULL, "getresgid"			},	/* 120 */
{ 1,    0,      sys_getpgid,            NULL, "getpgid"				},	/* 121 */
{ 1,    NF,     sys_setfsuid,           NULL, "setfsuid"			},	/* 122 */
{ 1,    NF,     sys_setfsgid,           NULL, "setfsgid"			},	/* 123 */
{ 1,    0,      sys_getsid,             NULL, "getsid"				},	/* 124 */
{ 2,    0,      sys_capget,             NULL, "capget"				},	/* 125 */
{ 2,    0,      sys_capset,             NULL, "capset"				},	/* 126 */
{},											/* 127 */
{},											/* 128 */
{},											/* 129 */
{ 2,    TS,     sys_rt_sigsuspend,      NULL, "rt_sigsuspend"			},	/* 130 */
{},											/* 131 */
{ 2,    TF,     sys_utime,              NULL, "utime"				},	/* 132 */
{ 3,    TF,     sys_mknod,              NULL, "mknod"				},	/* 133 */
{},											/* 134 */
{ 1,    0,      sys_personality,        NULL, "personality"			},	/* 135 */
{ 2,    0,      sys_ustat,              NULL, "ustat"				},	/* 136 */
{ 2,    TF,     sys_statfs,             NULL, "statfs"				},	/* 137 */
{ 2,    TD,     sys_fstatfs,            NULL, "fstatfs"				},	/* 138 */
{ 3,    0,      sys_sysfs,              NULL, "sysfs"				},	/* 139 */
{ 2,    0,      sys_getpriority,        NULL, "getpriority"			},	/* 140 */
{ 3,    0,      sys_setpriority,        NULL, "setpriority"			},	/* 141 */
{ 0,    0,      sys_sched_setparam,     NULL, "sched_setparam"			},	/* 142 */
{ 2,    0,      sys_sched_getparam,     NULL, "sched_getparam"			},	/* 143 */
{ 3,    0,      sys_sched_setscheduler, NULL, "sched_setscheduler"		},	/* 144 */
{ 1,    0,      sys_sched_getscheduler, NULL, "sched_getscheduler"		},	/* 145 */
{ 1,    0,      sys_sched_get_priority_max,     NULL, "sched_get_priority_max"  },	/* 146 */
{ 1,    0,      sys_sched_get_priority_min,     NULL, "sched_get_priority_min"  },	/* 147 */
{ 2,    0,      sys_sched_rr_get_interval,      NULL, "sched_rr_get_interval"   },	/* 148 */
{ 2,    0,      sys_mlock,              NULL, "mlock"				},	/* 149 */
{ 2,    0,      sys_munlock,            NULL, "munlock"				},	/* 150 */
{ 1,    0,      sys_mlockall,           NULL, "mlockall"			},	/* 151 */
{ 0,    0,      sys_munlockall,         NULL, "munlockall"			},	/* 152 */
{ 0,    0,      sys_vhangup,            NULL, "vhangup"				},	/* 153 */
{ 3,    0,      sys_modify_ldt,         NULL, "modify_ldt"			},	/* 154 */
{ 2,    TF,     sys_pivotroot,          NULL, "pivot_root"			},	/* 155 */
{},											/* 156 */
{ 5,    0,      sys_prctl,              NULL, "prctl"				},	/* 157 */
{ 2,    TP,     sys_arch_prctl,         NULL, "arch_prctl"			},	/* 158 */
{ 1,    0,      sys_adjtimex,           NULL, "adjtimex"			},	/* 159 */
{ 2,    0,      sys_setrlimit,          NULL, "setrlimit"			},	/* 160 */
{ 1,    TF,     sys_chroot,             NULL, "chroot"				},	/* 161 */
{ 0,    0,      sys_sync,               NULL, "sync"				},	/* 162 */
{ 1,    TF,     sys_acct,               NULL, "acct"				},	/* 163 */
{ 2,    0,      sys_settimeofday,       NULL, "settimeofday"			},	/* 164 */
{ 5,    TF,     sys_mount,              NULL, "mount"				},	/* 165 */
{ 2,    TF,     sys_umount2,            NULL, "umount"				},	/* 166 */
{ 2,    TF,     sys_swapon,             NULL, "swapon"				},	/* 167 */
{ 1,    TF,     sys_swapoff,            NULL, "swapoff"				},	/* 168 */
{ 4,    0,      sys_reboot,             NULL, "reboot"				},	/* 169 */
{ 2,    0,      sys_sethostname,        NULL, "sethostname"			},	/* 170 */
{ 2,    0,      sys_setdomainname,      NULL, "setdomainname"			},	/* 171 */
{ 1,    0,      sys_iopl,               NULL, "iopl"				},	/* 172 */
{ 3,    0,      sys_ioperm,             NULL, "ioperm"				},	/* 173 */
{ 2,    0,      sys_create_module,      NULL, "create_module"			},	/* 174 */
{ 3,    0,      sys_init_module,        NULL, "init_module"			},	/* 175 */
{ 2,    0,      sys_delete_module,      NULL, "delete_module"			},	/* 176 */
{},											/* 177 */
{},											/* 178 */
{ 4,    0,      sys_quotactl,           NULL, "quotactl"			},	/* 179 */
{},											/* 180 */
{},											/* 181 */
{},											/* 182 */
{},											/* 183 */
{},											/* 184 */
{},											/* 185 */
{ 0,    0,      sys_gettid,             NULL, "gettid"				},	/* 186 */
{ 4,    TD,     sys_readahead,          NULL, "readahead"			},	/* 187 */
{ 5,    TF,     sys_setxattr,           NULL, "setxattr"			},	/* 188 */
{ 5,    TF,     sys_setxattr,           NULL, "lsetxattr"			},	/* 189 */
{ 5,    TD,     sys_fsetxattr,          NULL, "fsetxattr"			},	/* 190 */
{ 4,    TF,     sys_getxattr,           NULL, "getxattr"			},	/* 191 */
{ 4,    TF,     sys_getxattr,           NULL, "lgetxattr"			},	/* 192 */
{ 4,    TD,     sys_fgetxattr,          NULL, "fgetxattr"			},	/* 193 */
{ 3,    TF,     sys_listxattr,          NULL, "listxattr"			},	/* 194 */
{ 3,    TF,     sys_listxattr,          NULL, "llistxattr"			},	/* 195 */
{ 3,    TD,     sys_flistxattr,         NULL, "flistxattr"			},	/* 196 */
{ 2,    TF,     sys_removexattr,        NULL, "removexattr"			},	/* 197 */
{ 2,    TF,     sys_removexattr,        NULL, "lremovexattr"			},	/* 198 */
{ 2,    TD,     sys_fremovexattr,       NULL, "fremovexattr"			},	/* 199 */
{ 2,    TS,     sys_kill,               NULL, "tkill"				},	/* 200 */
{ 1,    0,      sys_time,               NULL, "time"				},	/* 201 */
{ 6,    0,      sys_futex,              NULL, "futex"				},	/* 202 */
{ 3,    0,      sys_sched_setaffinity,  NULL, "sched_setaffinity"		},	/* 203 */
{ 3,    0,      sys_sched_getaffinity,  NULL, "sched_getaffinity"		},	/* 204 */
{},											/* 205 */
{ 2,    0,      sys_io_setup,           NULL, "io_setup"			},	/* 206 */
{ 1,    0,      sys_io_destroy,         NULL, "io_destroy"			},	/* 207 */
{ 5,    0,      sys_io_getevents,       NULL, "io_getevents"			},	/* 208 */
{ 3,    0,      sys_io_submit,          NULL, "io_submit"			},	/* 209 */
{ 3,    0,      sys_io_cancel,          NULL, "io_cancel"			},	/* 210 */
{},											/* 211 */
{ 4,    0,      sys_lookup_dcookie,     NULL, "lookup_dcookie"			},	/* 212 */
{ 1,    TD,     sys_epoll_create,       NULL, "epoll_create"			},	/* 213 */
{},											/* 214 */
{},											/* 215 */
{ 5,    0,      sys_remap_file_pages,   NULL, "remap_file_pages"		},	/* 216 */
{ 3,    TD,     sys_getdents64,         NULL, "getdents64"			},	/* 217 */
{ 1,    0,      sys_set_tid_address,    NULL, "set_tid_address"			},	/* 218 */
{ 0,    0,      sys_restart_syscall,    NULL, "restart_syscall"			},	/* 219 */
{ 5,    TI,     sys_semtimedop,         NULL, "semtimedop"			},	/* 220 */
{ 4,    TD,     sys_fadvise64_64,       NULL, "fadvise64"			},	/* 221 */
{},											/* 222 */
{ 4,    0,      sys_timer_settime,      NULL, "timer_settime"			},	/* 223 */
{ 2,    0,      sys_timer_gettime,      NULL, "timer_gettime"			},	/* 224 */
{ 1,    0,      sys_timer_getoverrun,   NULL, "timer_getoverrun"		},	/* 225 */
{ 1,    0,      sys_timer_delete,       NULL, "timer_delete"			},	/* 226 */
{ 2,    0,      sys_clock_settime,      NULL, "clock_settime"			},	/* 227 */
{ 2,    0,      sys_clock_gettime,      NULL, "clock_gettime"			},	/* 228 */
{ 2,    0,      sys_clock_getres,       NULL, "clock_getres"			},	/* 229 */
{ 4,    0,      sys_clock_nanosleep,    NULL, "clock_nanosleep"			},	/* 230 */
{ 1,    TP,     sys_exit,               NULL, "exit_group"			},	/* 231 */
{ 4,    TD,     sys_epoll_wait,         NULL, "epoll_wait"			},	/* 232 */
{ 4,    TD,     sys_epoll_ctl,          NULL, "epoll_ctl"			},	/* 233 */
{ 3,    TS,     sys_tgkill,             NULL, "tgkill"				},	/* 234 */
{ 2,    TF,     sys_utimes,             NULL, "utimes"				},	/* 235 */
{},											/* 236 */
{ 6,    0,      sys_mbind,              NULL, "mbind"				},	/* 237 */
{ 3,    0,      sys_set_mempolicy,      NULL, "set_mempolicy"			},	/* 238 */
{ 5,    0,      sys_get_mempolicy,      NULL, "get_mempolicy"			},	/* 239 */
{ 4,    0,      sys_mq_open,            NULL, "mq_open"				},	/* 240 */
{ 1,    0,      sys_mq_unlink,          NULL, "mq_unlink"			},	/* 241 */
{ 5,    0,      sys_mq_timedsend,       NULL, "mq_timedsend"			},	/* 242 */
{ 5,    0,      sys_mq_timedreceive,    NULL, "mq_timedreceive"			},	/* 243 */
{},											/* 244 */
{ 3,    0,      sys_mq_getsetattr,      NULL, "mq_getsetattr"			},	/* 245 */
{},											/* 246 */
{},											/* 247 */
{ 5,    0,      sys_add_key,            NULL, "add_key"				},	/* 248 */
{ 4,    0,      sys_request_key,        NULL, "request_key"			},	/* 249 */
{ 5,    0,      sys_keyctl,             NULL, "keyctl"				},	/* 250 */
{ 3,    0,      sys_ioprio_set,         NULL, "ioprio_set"			},	/* 251 */
{ 2,    0,      sys_ioprio_get,         NULL, "ioprio_get"			},	/* 252 */
{ 0,    TD,     sys_inotify_init,       NULL, "inotify_init"			},	/* 253 */
{ 3,    TD,     sys_inotify_add_watch,  NULL, "inotify_add_watch"		},	/* 254 */
{ 2,    TD,     sys_inotify_rm_watch,   NULL, "inotify_rm_watch"		},	/* 255 */
{ 4,    0,      sys_migrate_pages,      NULL, "migrate_pages"			},	/* 256 */
{ 4,    TD|TF,  sys_openat,             NULL, "openat"				},	/* 257 */
{ 3,    TD|TF,  sys_mkdirat,            NULL, "mkdirat"				},	/* 258 */
{ 4,    TD|TF,  sys_mknodat,            NULL, "mknodat"				},	/* 259 */
{ 5,    TD|TF,  sys_fchownat,           NULL, "fchownat"			},	/* 260 */
{ 3,    TD|TF,  sys_futimesat,          NULL, "futimesat"			},	/* 261 */
{ 4,    TD|TF,  sys_newfstatat,         NULL, "newfstatat"			},	/* 262 */
{ 3,    TD|TF,  sys_unlinkat,           NULL, "unlinkat"			},	/* 263 */
{ 4,    TD|TF,  sys_renameat,           NULL, "renameat"			},	/* 264 */
{ 5,    TD|TF,  sys_linkat,             NULL, "linkat"				},	/* 265 */
{ 3,    TD|TF,  sys_symlinkat,          NULL, "symlinkat"			},	/* 266 */
{ 4,    TD|TF,  sys_readlinkat,         NULL, "readlinkat"			},	/* 267 */
{ 3,    TD|TF,  sys_fchmodat,           NULL, "fchmodat"			},	/* 268 */
{ 3,    TD|TF,  sys_faccessat,          NULL, "faccessat"			},	/* 269 */
{ 6,    TD,     sys_pselect6,           NULL, "pselect6"			},	/* 270 */
{ 5,    TD,     sys_ppoll,              NULL, "ppoll"				},	/* 271 */
{ 1,    TP,     sys_unshare,            NULL, "unshare"				},	/* 272 */
{},											/* 273 */
{},											/* 274 */
{ 6,    TD,     sys_splice,             NULL, "splice"				},	/* 275 */
{ 4,    TD,     sys_tee,                NULL, "tee"				},	/* 276 */
{ 4,    TD,     sys_sync_file_range,    NULL, "sync_file_range"			},	/* 277 */
{},											/* 278 */
{},											/* 279 */
{ 4,    TD|TF,  sys_utimensat,          NULL, "utimensat"			},	/* 280 */
{ 6,    TD,     sys_epoll_pwait,        NULL, "epoll_pwait"			},	/* 281 */
{ 3,    TD|TS,  sys_signalfd,           NULL, "signalfd"			},	/* 282 */
{ 2,    TD,     sys_timerfd_create,     NULL, "timerfd_create"			},	/* 283 */
{ 1,    TD,     sys_eventfd,            NULL, "eventfd"				},	/* 284 */
{ 6,    TD,     sys_fallocate,          NULL, "fallocate"			},	/* 285 */
{ 4,    TD,     sys_timerfd_settime,    NULL, "timerfd_settime"			},	/* 286 */
{ 2,    TD,     sys_timerfd_gettime,    NULL, "timerfd_gettime"			},	/* 287 */
{ 4,    TN,     sys_accept4,            NULL, "accept4"				},	/* 288 */
{ 4,    TD|TS,  sys_signalfd4,          NULL, "signalfd4"			},	/* 289 */
{ 2,    TD,     sys_eventfd2,           NULL, "eventfd2"			},	/* 290 */
{ 1,    TD,     sys_epoll_create1,      NULL, "epoll_create1"			},	/* 291 */
{ 3,    TD,     sys_dup3,               NULL, "dup3"				},	/* 292 */
{ 2,    TD,     sys_pipe2,              NULL, "pipe2"				},	/* 293 */
{ 1,    TD,     sys_inotify_init1,      NULL, "inotify_init1"			},	/* 294 */
{},											/* 295 */
{},											/* 296 */
{},											/* 297 */
{ 5,    TD,     sys_perf_event_open,    NULL, "perf_event_open"			},	/* 298 */
{},											/* 299 */
{ 2,    TD,     sys_fanotify_init,      NULL, "fanotify_init"			},	/* 300 */
{ 5,    TD|TF,  sys_fanotify_mark,      NULL, "fanotify_mark"			},	/* 301 */
{ 4,    0,      sys_prlimit64,          NULL, "prlimit64"			},	/* 302 */
{ 5,    TD|TF,  sys_name_to_handle_at,  NULL, "name_to_handle_at"		},	/* 303 */
{ 3,    TD,     sys_open_by_handle_at,  NULL, "open_by_handle_at"		},	/* 304 */
{ 2,    0,      sys_clock_adjtime,      NULL, "clock_adjtime"			},	/* 305 */
{ 1,    TD,     sys_syncfs,             NULL, "syncfs"				},	/* 306 */
{},											/* 307 */
{ 2,    TD,     sys_setns,              NULL, "setns"				},	/* 308 */
{ 3,    0,      sys_getcpu,             NULL, "getcpu"				},	/* 309 */
{},											/* 310 */
{},											/* 311 */

[312 ... 511] = {								},

{ 4,    TS,     sys_rt_sigaction,       NULL, "rt_sigaction"			},	/* 512 */
{ 0,    TS,     sys_rt_sigreturn,       NULL, "rt_sigreturn"			},	/* 513 */
{ 3,    TD,     sys_ioctl,              NULL, "ioctl"				},	/* 514 */
{ 3,    TD,     sys_readv,              NULL, "readv"				},	/* 515 */
{ 3,    TD,     sys_writev,             NULL, "writev"				},	/* 516 */
{ 6,    TN,     sys_recvfrom,           NULL, "recvfrom"			},	/* 517 */
{ 3,    TN,     sys_sendmsg,            NULL, "sendmsg"				},	/* 518 */
{ 5,    TN,     sys_recvmsg,            NULL, "recvmsg"				},	/* 519 */
{ 3,    TF|TP,  sys_execve,             NULL, "execve"				},	/* 520 */
{ 4,    0,      sys_ptrace,             NULL, "ptrace"				},	/* 521 */
{ 2,    TS,     sys_rt_sigpending,      NULL, "rt_sigpending"			},	/* 522 */
{ 4,    TS,     sys_rt_sigtimedwait,    NULL, "rt_sigtimedwait"			},	/* 523 */
{ 3,    TS,     sys_rt_sigqueueinfo,    NULL, "rt_sigqueueinfo"			},	/* 524 */
{ 2,    TS,     sys_sigaltstack,        NULL, "sigaltstack"			},	/* 525 */
{ 3,    0,      sys_timer_create,       NULL, "timer_create"			},	/* 526 */
{ 2,    0,      sys_mq_notify,          NULL, "mq_notify"			},	/* 527 */
{ 4,    0,      sys_kexec_load,         NULL, "kexec_load"			},	/* 528 */
{ 5,    TP,     sys_waitid,             NULL, "waitid"				},	/* 529 */
{ 2,    0,      sys_set_robust_list,    NULL, "set_robust_list"			},	/* 530 */
{ 3,    0,      sys_get_robust_list,    NULL, "get_robust_list"			},	/* 531 */
{ 4,    TD,     sys_vmsplice,           NULL, "vmsplice"			},	/* 532 */
{ 6,    0,      sys_move_pages,         NULL, "move_pages"			},	/* 533 */
{ 5,    TD,     sys_preadv,             NULL, "preadv"				},	/* 534 */
{ 5,    TD,     sys_pwritev,            NULL, "pwritev"				},	/* 535 */
{ 4,    TP|TS,  sys_rt_tgsigqueueinfo,  NULL, "rt_tgsigqueueinfo"		},	/* 536 */
{ 5,    TN,     sys_recvmmsg,           NULL, "recvmmsg"			},	/* 537 */
{ 4,    TN,     sys_sendmmsg,           NULL, "sendmmsg"			},	/* 538 */
{ 6,    0,      sys_process_vm_readv,   NULL, "process_vm_readv"		},	/* 539 */
{ 6,    0,      sys_process_vm_writev,  NULL, "process_vm_writev"		},	/* 540 */
