/*
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995 Rick Sladkey <jrs@world.std.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

{ 0,	0,	sys_restart_syscall,	NULL, "restart_syscall"			}, /* 0 */
{ 1,	TP,	sys_exit,		NULL, "_exit",				}, /* 1 */
{ 0,	TP,	sys_fork,		NULL, "fork",				}, /* 2 */
{ 3,	TD,	sys_read,		NULL, "read",				}, /* 3 */
{ 3,	TD,	sys_write,		NULL, "write",				}, /* 4 */
{ 3,	TD|TF,	sys_open,		NULL, "open"				}, /* 5 */
{ 1,	TD,	sys_close,		NULL, "close"				}, /* 6 */
{ 3,	TP,	sys_waitpid,		NULL, "waitpid",			}, /* 7 */
{ 2,	TD|TF,	sys_creat,		NULL, "creat"				}, /* 8 */
{ 2,	TF,	sys_link,		NULL, "link"				}, /* 9 */
{ 1,	TF,	sys_unlink,		NULL, "unlink"				}, /* 10 */
{ 3,	TF|TP,	sys_execve,		NULL, "execve"				}, /* 11 */
{ 1,	TF,	sys_chdir,		NULL, "chdir"				}, /* 12 */
{ 1,	0,	sys_time,		NULL, "time"				}, /* 13 */
{ 3,	TF,	sys_mknod,		NULL, "mknod"				}, /* 14 */
{ 2,	TF,	sys_chmod,		NULL, "chmod"				}, /* 15 */
{ 3,	TF,	sys_chown,		NULL, "lchown"				}, /* 16 */
{ 0,	0,	sys_break,		NULL, "break"				}, /* 17 */
{ 2,	TF,	sys_oldstat,		NULL, "oldstat"				}, /* 18 */
{ 3,	TD,	sys_lseek,		NULL, "lseek"				}, /* 19 */
{ 0,	0,	sys_getpid,		NULL, "getpid"				}, /* 20 */
{ 5,	TF,	sys_mount,		NULL, "mount"				}, /* 21 */
{ 1,	TF,	sys_umount,		NULL, "oldumount"			}, /* 22 */
{ 1,	0,	sys_setuid,		NULL, "setuid"				}, /* 23 */
{ 0,	NF,	sys_getuid,		NULL, "getuid"				}, /* 24 */
{ 1,	0,	sys_stime,		NULL, "stime"				}, /* 25 */
{ 4,	0,	sys_ptrace,		NULL, "ptrace"				}, /* 26 */
{ 1,	0,	sys_alarm,		NULL, "alarm"				}, /* 27 */
{ 2,	TD,	sys_oldfstat,		NULL, "oldfstat"			}, /* 28 */
{ 0,	TS,	sys_pause,		NULL, "pause"				}, /* 29 */
{ 2,	TF,	sys_utime,		NULL, "utime"				}, /* 30 */
{ 2,	0,	sys_stty,		NULL, "stty"				}, /* 31 */
{ 2,	0,	sys_gtty,		NULL, "gtty"				}, /* 32 */
{ 2,	TF,	sys_access,		NULL, "access"				}, /* 33 */
{ 1,	0,	sys_nice,		NULL, "nice"				}, /* 34 */
{ 0,	0,	sys_ftime,		NULL, "ftime"				}, /* 35 */
{ 0,	0,	sys_sync,		NULL, "sync"				}, /* 36 */
{ 2,	TS,	sys_kill,		NULL, "kill"				}, /* 37 */
{ 2,	TF,	sys_rename,		NULL, "rename"				}, /* 38 */
{ 2,	TF,	sys_mkdir,		NULL, "mkdir"				}, /* 39 */
{ 1,	TF,	sys_rmdir,		NULL, "rmdir"				}, /* 40 */
{ 1,	TD,	sys_dup,		NULL, "dup"				}, /* 41 */
{ 1,	TD,	sys_pipe,		NULL, "pipe"				}, /* 42 */
{ 1,	0,	sys_times,		NULL, "times"				}, /* 43 */
{ 0,	0,	sys_prof,		NULL, "prof"				}, /* 44 */
{ 1,	0,	sys_brk,		NULL, "brk"				}, /* 45 */
{ 1,	0,	sys_setgid,		NULL, "setgid"				}, /* 46 */
{ 0,	NF,	sys_getgid,		NULL, "getgid"				}, /* 47 */
{ 3,	TS,	sys_signal,		NULL, "signal"				}, /* 48 */
{ 0,	NF,	sys_geteuid,		NULL, "geteuid"				}, /* 49 */
{ 0,	NF,	sys_getegid,		NULL, "getegid"				}, /* 50 */
{ 1,	TF,	sys_acct,		NULL, "acct"				}, /* 51 */
{ 2,	TF,	sys_umount2,		NULL, "umount"				}, /* 52 */
{ 0,	0,	sys_lock,		NULL, "lock"				}, /* 53 */
{ 3,	TD,	sys_ioctl,		NULL, "ioctl"				}, /* 54 */
{ 3,	TD,	sys_fcntl,		NULL, "fcntl"				}, /* 55 */
{ 0,	0,	sys_mpx,		NULL, "mpx"				}, /* 56 */
{ 2,	0,	sys_setpgid,		NULL, "setpgid"				}, /* 57 */
{ 2,	0,	sys_ulimit,		NULL, "ulimit"				}, /* 58 */
{ 1,	0,	sys_oldolduname,	NULL, "oldolduname"			}, /* 59 */
{ 1,	0,	sys_umask,		NULL, "umask"				}, /* 60 */
{ 1,	TF,	sys_chroot,		NULL, "chroot"				}, /* 61 */
{ 2,	0,	sys_ustat,		NULL, "ustat"				}, /* 62 */
{ 2,	TD,	sys_dup2,		NULL, "dup2"				}, /* 63 */
{ 0,	0,	sys_getppid,		NULL, "getppid"				}, /* 64 */
{ 0,	0,	sys_getpgrp,		NULL, "getpgrp"				}, /* 65 */
{ 0,	0,	sys_setsid,		NULL, "setsid"				}, /* 66 */
{ 3,	TS,	sys_sigaction,		NULL, "sigaction"			}, /* 67 */
{ 0,	TS,	sys_siggetmask,		NULL, "sgetmask"			}, /* 68 */
{ 1,	TS,	sys_sigsetmask,		NULL, "ssetmask"			}, /* 69 */
{ 2,	0,	sys_setreuid,		NULL, "setreuid"			}, /* 70 */
{ 2,	0,	sys_setregid,		NULL, "setregid"			}, /* 71 */
{ 3,	TS,	sys_sigsuspend,		NULL, "sigsuspend"			}, /* 72 */
{ 1,	TS,	sys_sigpending,		NULL, "sigpending"			}, /* 73 */
{ 2,	0,	sys_sethostname,	NULL, "sethostname"			}, /* 74 */
{ 2,	0,	sys_setrlimit,		NULL, "setrlimit"			}, /* 75 */
{ 2,	0,	sys_getrlimit,		NULL, "old_getrlimit"			}, /* 76 */
{ 2,	0,	sys_getrusage,		NULL, "getrusage"			}, /* 77 */
{ 2,	0,	sys_gettimeofday,	NULL, "gettimeofday"			}, /* 78 */
{ 2,	0,	sys_settimeofday,	NULL, "settimeofday"			}, /* 79 */
{ 2,	0,	sys_getgroups,		NULL, "getgroups"			}, /* 80 */
{ 2,	0,	sys_setgroups,		NULL, "setgroups"			}, /* 81 */
{ 1,	TD,	sys_oldselect,		NULL, "oldselect"			}, /* 82 */
{ 2,	TF,	sys_symlink,		NULL, "symlink"				}, /* 83 */
{ 2,	TF,	sys_oldlstat,		NULL, "oldlstat"			}, /* 84 */
{ 3,	TF,	sys_readlink,		NULL, "readlink"			}, /* 85 */
{ 1,	TF,	sys_uselib,		NULL, "uselib"				}, /* 86 */
{ 2,	TF,	sys_swapon,		NULL, "swapon"				}, /* 87 */
{ 4,	0,	sys_reboot,		NULL, "reboot"				}, /* 88 */
{ 3,	TD,	sys_readdir,		NULL, "readdir"				}, /* 89 */
{ 6,	TD,	sys_old_mmap,		NULL, "old_mmap"			}, /* 90 */
{ 2,	0,	sys_munmap,		NULL, "munmap"				}, /* 91 */
{ 2,	TF,	sys_truncate,		NULL, "truncate"			}, /* 92 */
{ 2,	TD,	sys_ftruncate,		NULL, "ftruncate"			}, /* 93 */
{ 2,	TD,	sys_fchmod,		NULL, "fchmod"				}, /* 94 */
{ 3,	TD,	sys_fchown,		NULL, "fchown"				}, /* 95 */
{ 2,	0,	sys_getpriority,	NULL, "getpriority"			}, /* 96 */
{ 3,	0,	sys_setpriority,	NULL, "setpriority"			}, /* 97 */
{ 4,	0,	sys_profil,		NULL, "profil"				}, /* 98 */
{ 2,	TF,	sys_statfs,		NULL, "statfs"				}, /* 99 */
{ 2,	TD,	sys_fstatfs,		NULL, "fstatfs"				}, /* 100 */
{ 3,	0,	sys_ioperm,		NULL, "ioperm"				}, /* 101 */
{ 2,	TD,	sys_socketcall,		NULL, "socketcall"			}, /* 102 */
{ 3,	0,	sys_syslog,		NULL, "syslog"				}, /* 103 */
{ 3,	0,	sys_setitimer,		NULL, "setitimer"			}, /* 104 */
{ 2,	0,	sys_getitimer,		NULL, "getitimer"			}, /* 105 */
{ 2,	TF,	sys_stat,		NULL, "stat"				}, /* 106 */
{ 2,	TF,	sys_lstat,		NULL, "lstat"				}, /* 107 */
{ 2,	TD,	sys_fstat,		NULL, "fstat"				}, /* 108 */
{ 1,	0,	sys_olduname,		NULL, "olduname"			}, /* 109 */
{ 1,	0,	sys_iopl,		NULL, "iopl"				}, /* 110 */
{ 0,	0,	sys_vhangup,		NULL, "vhangup"				}, /* 111 */
{ 0,	0,	sys_idle,		NULL, "idle"				}, /* 112 */
{ 1,	0,	sys_vm86old,		NULL, "vm86old"				}, /* 113 */
{ 4,	TP,	sys_wait4,		NULL, "wait4",				}, /* 114 */
{ 1,	TF,	sys_swapoff,		NULL, "swapoff"				}, /* 115 */
{ 1,	0,	sys_sysinfo,		NULL, "sysinfo"				}, /* 116 */
{ 6,	TI,	sys_ipc,		NULL, "ipc",				}, /* 117 */
{ 1,	TD,	sys_fsync,		NULL, "fsync"				}, /* 118 */
{ 0,	TS,	sys_sigreturn,		NULL, "sigreturn"			}, /* 119 */
{ 5,	TP,	sys_clone,		NULL, "clone"				}, /* 120 */
{ 2,	0,	sys_setdomainname,	NULL, "setdomainname"			}, /* 121 */
{ 1,	0,	sys_uname,		NULL, "uname"				}, /* 122 */
{ 3,	0,	sys_modify_ldt,		NULL, "modify_ldt"			}, /* 123 */
{ 1,	0,	sys_adjtimex,		NULL, "adjtimex"			}, /* 124 */
{ 3,	0,	sys_mprotect,		NULL, "mprotect"			}, /* 125 */
{ 3,	TS,	sys_sigprocmask,	NULL, "sigprocmask"			}, /* 126 */
{ 2,	0,	sys_create_module,	NULL, "create_module"			}, /* 127 */
{ 3,	0,	sys_init_module,	NULL, "init_module"			}, /* 128 */
{ 2,	0,	sys_delete_module,	NULL, "delete_module"			}, /* 129 */
{ 1,	0,	sys_get_kernel_syms,	NULL, "get_kernel_syms"			}, /* 130 */
{ 4,	0,	sys_quotactl,		NULL, "quotactl"			}, /* 131 */
{ 1,	0,	sys_getpgid,		NULL, "getpgid"				}, /* 132 */
{ 1,	TD,	sys_fchdir,		NULL, "fchdir"				}, /* 133 */
{ 0,	0,	sys_bdflush,		NULL, "bdflush"				}, /* 134 */
{ 3,	0,	sys_sysfs,		NULL, "sysfs",				}, /* 135 */
{ 1,	0,	sys_personality,	NULL, "personality"			}, /* 136 */
{ 5,	0,	sys_afs_syscall,	NULL, "afs_syscall"			}, /* 137 */
{ 1,	NF,	sys_setfsuid,		NULL, "setfsuid"			}, /* 138 */
{ 1,	NF,	sys_setfsgid,		NULL, "setfsgid"			}, /* 139 */
{ 5,	TD,	sys_llseek,		NULL, "_llseek"				}, /* 140 */
{ 3,	TD,	sys_getdents,		NULL, "getdents"			}, /* 141 */
{ 5,	TD,	sys_select,		NULL, "select"				}, /* 142 */
{ 2,	TD,	sys_flock,		NULL, "flock"				}, /* 143 */
{ 3,	0,	sys_msync,		NULL, "msync"				}, /* 144 */
{ 3,	TD,	sys_readv,		NULL, "readv",				}, /* 145 */
{ 3,	TD,	sys_writev,		NULL, "writev",				}, /* 146 */
{ 1,	0,	sys_getsid,		NULL, "getsid"				}, /* 147 */
{ 1,	TD,	sys_fdatasync,		NULL, "fdatasync"			}, /* 148 */
{ 1,	0,	sys_sysctl,		NULL, "_sysctl"				}, /* 149 */
{ 2,	0,	sys_mlock,		NULL, "mlock"				}, /* 150 */
{ 2,	0,	sys_munlock,		NULL, "munlock"				}, /* 151 */
{ 1,	0,	sys_mlockall,		NULL, "mlockall"			}, /* 152 */
{ 0,	0,	sys_munlockall,		NULL, "munlockall"			}, /* 153 */
{ 0,	0,	sys_sched_setparam,	NULL, "sched_setparam"			}, /* 154 */
{ 2,	0,	sys_sched_getparam,	NULL, "sched_getparam"			}, /* 155 */
{ 3,	0,	sys_sched_setscheduler,	NULL, "sched_setscheduler"		}, /* 156 */
{ 1,	0,	sys_sched_getscheduler,	NULL, "sched_getscheduler"		}, /* 157 */
{ 0,	0,	sys_sched_yield,	NULL, "sched_yield"			}, /* 158 */
{ 1,	0,	sys_sched_get_priority_max,NULL, "sched_get_priority_max"	}, /* 159 */
{ 1,	0,	sys_sched_get_priority_min,NULL, "sched_get_priority_min"	}, /* 160 */
{ 2,	0,	sys_sched_rr_get_interval,NULL, "sched_rr_get_interval"		}, /* 161 */
{ 2,	0,	sys_nanosleep,		NULL, "nanosleep"			}, /* 162 */
{ 5,	0,	sys_mremap,		NULL, "mremap"				}, /* 163 */
{ 3,	0,	sys_setresuid,		NULL, "setresuid"			}, /* 164 */
{ 3,	0,	sys_getresuid,		NULL, "getresuid"			}, /* 165 */
{ 5,	0,	sys_vm86,		NULL, "vm86"				}, /* 166 */
{ 5,	0,	sys_query_module,	NULL, "query_module"			}, /* 167 */
{ 3,	TD,	sys_poll,		NULL, "poll"				}, /* 168 */
{ 3,	0,	sys_nfsservctl,		NULL, "nfsservctl"			}, /* 169 */
{ 3,	0,	sys_setresgid,		NULL, "setresgid"			}, /* 170 */
{ 3,	0,	sys_getresgid,		NULL, "getresgid"			}, /* 171 */
{ 5,	0,	sys_prctl,		NULL, "prctl"				}, /* 172 */
{ 0,	TS,	sys_rt_sigreturn,	NULL, "rt_sigreturn"			}, /* 173 */
{ 4,	TS,	sys_rt_sigaction,	NULL, "rt_sigaction"			}, /* 174 */
{ 4,	TS,	sys_rt_sigprocmask,	NULL, "rt_sigprocmask"			}, /* 175 */
{ 2,	TS,	sys_rt_sigpending,	NULL, "rt_sigpending"			}, /* 176 */
{ 4,	TS,	sys_rt_sigtimedwait,	NULL, "rt_sigtimedwait"			}, /* 177 */
{ 3,	TS,	sys_rt_sigqueueinfo,    NULL, "rt_sigqueueinfo"			}, /* 178 */
{ 2,	TS,	sys_rt_sigsuspend,	NULL, "rt_sigsuspend"			}, /* 179 */

{ 5,	TD,	sys_pread,		NULL, "pread64",			}, /* 180 */
{ 5,	TD,	sys_pwrite,		NULL, "pwrite64",			}, /* 181 */
{ 3,	TF,	sys_chown,		NULL, "chown"				}, /* 182 */
{ 2,	TF,	sys_getcwd,		NULL, "getcwd"				}, /* 183 */
{ 2,	0,	sys_capget,		NULL, "capget"				}, /* 184 */
{ 2,	0,	sys_capset,		NULL, "capset"				}, /* 185 */
{ 2,	TS,	sys_sigaltstack,	NULL, "sigaltstack"			}, /* 186 */
{ 4,	TD|TN,	sys_sendfile,		NULL, "sendfile"			}, /* 187 */
{ 5,	0,	sys_getpmsg,		NULL, "getpmsg"				}, /* 188 */
{ 5,	0,	sys_putpmsg,		NULL, "putpmsg"				}, /* 189 */
{ 0,	TP,	sys_vfork,		NULL, "vfork"				}, /* 190 */
{ 2,	0,	sys_getrlimit,		NULL, "getrlimit"			}, /* 191 */
{ 6,	TD,	sys_mmap,		NULL, "mmap2"				}, /* 192 */
{ 3,	TF,	sys_truncate64,		NULL, "truncate64"			}, /* 193 */
{ 3,	TD,	sys_ftruncate64,	NULL, "ftruncate64"			}, /* 194 */
{ 2,	TF,	sys_stat64,		NULL, "stat64"				}, /* 195 */
{ 2,	TF,	sys_lstat64,		NULL, "lstat64"				}, /* 196 */
{ 2,	TD,	sys_fstat64,		NULL, "fstat64"				}, /* 197 */
{ 3,	TF,	sys_chown,		NULL, "lchown32"			}, /* 198 */
{ 0,	NF,	sys_getuid,		NULL, "getuid32"			}, /* 199 */

{ 0,	NF,	sys_getgid,		NULL, "getgid32"			}, /* 200 */
{ 0,	NF,	sys_geteuid,		NULL, "geteuid32"			}, /* 201 */
{ 0,	NF,	sys_getegid,		NULL, "getegid32"			}, /* 202 */
{ 2,	0,	sys_setreuid,		NULL, "setreuid32"			}, /* 203 */
{ 2,	0,	sys_setregid,		NULL, "setregid32"			}, /* 204 */
{ 2,	0,	sys_getgroups32,	NULL, "getgroups32"			}, /* 205 */
{ 2,	0,	sys_setgroups32,	NULL, "setgroups32"			}, /* 206 */
{ 3,	TD,	sys_fchown,		NULL, "fchown32"			}, /* 207 */
{ 3,	0,	sys_setresuid,		NULL, "setresuid32"			}, /* 208 */
{ 3,	0,	sys_getresuid,		NULL, "getresuid32"			}, /* 209 */
{ 3,	0,	sys_setresgid,		NULL, "setresgid32"			}, /* 210 */
{ 3,	0,	sys_getresgid,		NULL, "getresgid32"			}, /* 211 */
{ 3,	TF,	sys_chown,		NULL, "chown32"				}, /* 212 */
{ 1,	0,	sys_setuid,		NULL, "setuid32"			}, /* 213 */
{ 1,	0,	sys_setgid,		NULL, "setgid32"			}, /* 214 */
{ 1,	NF,	sys_setfsuid,		NULL, "setfsuid32"			}, /* 215 */
{ 1,	NF,	sys_setfsgid,		NULL, "setfsgid32"			}, /* 216 */
{ 2,	TF,	sys_pivotroot,		NULL, "pivot_root"			}, /* 217 */
{ 3,	0,	sys_mincore,		NULL, "mincore"				}, /* 218 */
{ 3,	0,	sys_madvise,		NULL, "madvise"				}, /* 219 */
{ 3,	TD,	sys_getdents64,		NULL, "getdents64"			}, /* 220 */
{ 3,	TD,	sys_fcntl,		NULL, "fcntl64"				}, /* 221 */
{ 6,	0,	NULL,			NULL, NULL				}, /* 222 */
{ 5,	0,	sys_security,		NULL, "security"			}, /* 223 */
{ 0,	0,	sys_gettid,		NULL, "gettid"				}, /* 224 */
{ 4,	TD,	sys_readahead,		NULL, "readahead"			}, /* 225 */
{ 5,	TF,	sys_setxattr,		NULL, "setxattr"			}, /* 226 */
{ 5,	TF,	sys_setxattr,		NULL, "lsetxattr"			}, /* 227 */
{ 5,	TD,	sys_fsetxattr,		NULL, "fsetxattr"			}, /* 228 */
{ 4,	TF,	sys_getxattr,		NULL, "getxattr"			}, /* 229 */
{ 4,	TF,	sys_getxattr,		NULL, "lgetxattr"			}, /* 230 */
{ 4,	TD,	sys_fgetxattr,		NULL, "fgetxattr"			}, /* 231 */
{ 3,	TF,	sys_listxattr,		NULL, "listxattr"			}, /* 232 */
{ 3,	TF,	sys_listxattr,		NULL, "llistxattr"			}, /* 233 */
{ 3,	TD,	sys_flistxattr,		NULL, "flistxattr"			}, /* 234 */
{ 2,	TF,	sys_removexattr,	NULL, "removexattr"			}, /* 235 */
{ 2,	TF,	sys_removexattr,	NULL, "lremovexattr"			}, /* 236 */
{ 2,	TD,	sys_fremovexattr,	NULL, "fremovexattr"			}, /* 237 */
{ 2,	TS,	sys_kill,		NULL, "tkill"				}, /* 238 */
{ 4,	TD|TN,	sys_sendfile64,		NULL, "sendfile64"			}, /* 239 */
{ 6,	0,	sys_futex,		NULL, "futex"				}, /* 240 */
{ 3,	0,	sys_sched_setaffinity,	NULL, "sched_setaffinity"		},/* 241 */
{ 3,	0,	sys_sched_getaffinity,	NULL, "sched_getaffinity"		},/* 242 */
{ 1,	0,	sys_set_thread_area,	NULL, "set_thread_area"			}, /* 243 */
{ 1,	0,	sys_get_thread_area,	NULL, "get_thread_area"			}, /* 244 */
{ 2,	0,	sys_io_setup,		NULL, "io_setup"			}, /* 245 */
{ 1,	0,	sys_io_destroy,		NULL, "io_destroy"			}, /* 246 */
{ 5,	0,	sys_io_getevents,	NULL, "io_getevents"			}, /* 247 */
{ 3,	0,	sys_io_submit,		NULL, "io_submit"			}, /* 248 */
{ 3,	0,	sys_io_cancel,		NULL, "io_cancel"			}, /* 249 */
{ 5,	TD,	sys_fadvise64,		NULL, "fadvise64"			}, /* 250 */
{ 6,	0,	NULL,			NULL					}, /* 251 */
{ 1,	TP,	sys_exit,		NULL, "exit_group"			}, /* 252 */
{ 4,	0,	sys_lookup_dcookie,	NULL, "lookup_dcookie"			}, /* 253 */
{ 1,	TD,	sys_epoll_create,	NULL, "epoll_create"			}, /* 254 */
{ 4,	TD,	sys_epoll_ctl,		NULL, "epoll_ctl"			}, /* 255 */
{ 4,	TD,	sys_epoll_wait,		NULL, "epoll_wait"			}, /* 256 */
{ 5,	0,	sys_remap_file_pages,	NULL, "remap_file_pages"		}, /* 257 */
{ 1,	0,	sys_set_tid_address,	NULL, "set_tid_address"			}, /* 258 */
{ 3,	0,	sys_timer_create,	NULL, "timer_create"			}, /* 259 */
{ 4,	0,	sys_timer_settime,	NULL, "timer_settime"			}, /* 260 */
{ 2,	0,	sys_timer_gettime,	NULL, "timer_gettime"			}, /* 261 */
{ 1,	0,	sys_timer_getoverrun,	NULL, "timer_getoverrun"		}, /* 262 */
{ 1,	0,	sys_timer_delete,	NULL, "timer_delete"			}, /* 263 */
{ 2,	0,	sys_clock_settime,	NULL, "clock_settime"			}, /* 264 */
{ 2,	0,	sys_clock_gettime,	NULL, "clock_gettime"			}, /* 265 */
{ 2,	0,	sys_clock_getres,	NULL, "clock_getres"			}, /* 266 */
{ 4,	0,	sys_clock_nanosleep,	NULL, "clock_nanosleep"			}, /* 267 */
{ 3,	TF,	sys_statfs64,		NULL, "statfs64"			}, /* 268 */
{ 3,	TD,	sys_fstatfs64,		NULL, "fstatfs64"			}, /* 269 */
{ 3,	TS,	sys_tgkill,		NULL, "tgkill"				}, /* 270 */
{ 2,	TF,	sys_utimes,		NULL, "utimes"				}, /* 271 */
{ 6,	TD,	sys_fadvise64_64,	NULL, "fadvise64_64"			}, /* 272 */
{ 5,	0,	sys_vserver,		NULL, "vserver"				}, /* 273 */
{ 6,	0,	sys_mbind,		NULL, "mbind"				}, /* 274 */
{ 5,	0,	sys_get_mempolicy,	NULL, "get_mempolicy"			}, /* 275 */
{ 3,	0,	sys_set_mempolicy,	NULL, "set_mempolicy"			}, /* 276 */
{ 4,	0,	sys_mq_open,		NULL, "mq_open"				}, /* 277 */
{ 1,	0,	sys_mq_unlink,		NULL, "mq_unlink"			}, /* 278 */
{ 5,	0,	sys_mq_timedsend,	NULL, "mq_timedsend"			}, /* 279 */
{ 5,	0,	sys_mq_timedreceive,	NULL, "mq_timedreceive"			}, /* 280 */
{ 2,	0,	sys_mq_notify,		NULL, "mq_notify"			}, /* 281 */
{ 3,	0,	sys_mq_getsetattr,	NULL, "mq_getsetattr"			}, /* 282 */
{ 4,	0,	sys_kexec_load,		NULL, "kexec_load"			}, /* 283 */
{ 5,	TP,	sys_waitid,		NULL, "waitid",				}, /* 284 */
{ 6,	0,	NULL,			NULL					}, /* 285 */
{ 5,	0,	sys_add_key,		NULL, "add_key"				}, /* 286 */
{ 4,	0,	sys_request_key,	NULL, "request_key"			}, /* 287 */
{ 5,	0,	sys_keyctl,		NULL, "keyctl"				}, /* 288 */
{ 3,	0,	sys_ioprio_set,		NULL, "ioprio_set"			}, /* 289 */
{ 2,	0,	sys_ioprio_get,		NULL, "ioprio_get"			}, /* 290 */
{ 0,	TD,	sys_inotify_init,	NULL, "inotify_init"			}, /* 291 */
{ 3,	TD,	sys_inotify_add_watch,	NULL, "inotify_add_watch"		}, /* 292 */
{ 2,	TD,	sys_inotify_rm_watch,	NULL, "inotify_rm_watch"		}, /* 293 */
{ 4,	0,	sys_migrate_pages,	NULL, "migrate_pages"			}, /* 294 */
{ 4,	TD|TF,	sys_openat,		NULL, "openat"				}, /* 295 */
{ 3,	TD|TF,	sys_mkdirat,		NULL, "mkdirat"				}, /* 296 */
{ 4,	TD|TF,	sys_mknodat,		NULL, "mknodat"				}, /* 297 */
{ 5,	TD|TF,	sys_fchownat,		NULL, "fchownat"			}, /* 298 */
{ 3,	TD|TF,	sys_futimesat,		NULL, "futimesat"			}, /* 299 */
{ 4,	TD|TF,	sys_newfstatat,		NULL, "fstatat64"			}, /* 300 */
{ 3,	TD|TF,	sys_unlinkat,		NULL, "unlinkat"			}, /* 301 */
{ 4,	TD|TF,	sys_renameat,		NULL, "renameat"			}, /* 302 */
{ 5,	TD|TF,	sys_linkat,		NULL, "linkat"				}, /* 303 */
{ 3,	TD|TF,	sys_symlinkat,		NULL, "symlinkat"			}, /* 304 */
{ 4,	TD|TF,	sys_readlinkat,		NULL, "readlinkat"			}, /* 305 */
{ 3,	TD|TF,	sys_fchmodat,		NULL, "fchmodat"			}, /* 306 */
{ 3,	TD|TF,	sys_faccessat,		NULL, "faccessat"			}, /* 307 */
{ 6,	TD,	sys_pselect6,		NULL, "pselect6"			}, /* 308 */
{ 5,	TD,	sys_ppoll,		NULL, "ppoll"				}, /* 309 */
{ 1,	TP,	sys_unshare,		NULL, "unshare"				}, /* 310 */
{ 2,	0,	sys_set_robust_list,	NULL, "set_robust_list"			}, /* 311 */
{ 3,	0,	sys_get_robust_list,	NULL, "get_robust_list"			}, /* 312 */
{ 6,	TD,	sys_splice,		NULL, "splice"				}, /* 313 */
{ 4,	TD,	sys_sync_file_range,	NULL, "sync_file_range"			}, /* 314 */
{ 4,	TD,	sys_tee,		NULL, "tee"				}, /* 315 */
{ 4,	TD,	sys_vmsplice,		NULL, "vmsplice"			}, /* 316 */
{ 6,	0,	sys_move_pages,		NULL, "move_pages"			}, /* 317 */
{ 3,	0,	sys_getcpu,		NULL, "getcpu"				}, /* 318 */
{ 6,	TD,	sys_epoll_pwait,	NULL, "epoll_pwait"			}, /* 319 */
{ 4,	TD|TF,	sys_utimensat,		NULL, "utimensat"			}, /* 320 */
{ 3,	TD|TS,	sys_signalfd,		NULL, "signalfd"			}, /* 321 */
{ 2,	TD,	sys_timerfd_create,	NULL, "timerfd_create"			}, /* 322 */
{ 1,	TD,	sys_eventfd,		NULL, "eventfd"				}, /* 323 */
{ 6,	TD,	sys_fallocate,		NULL, "fallocate"			}, /* 324 */
{ 4,	TD,	sys_timerfd_settime,	NULL, "timerfd_settime"			}, /* 325 */
{ 2,	TD,	sys_timerfd_gettime,	NULL, "timerfd_gettime"			}, /* 326 */
{ 4,	TD|TS,	sys_signalfd4,		NULL, "signalfd4"			}, /* 327 */
{ 2,	TD,	sys_eventfd2,		NULL, "eventfd2"			}, /* 328 */
{ 1,	TD,	sys_epoll_create1,	NULL, "epoll_create1"			}, /* 329 */
{ 3,	TD,	sys_dup3,		NULL, "dup3"				}, /* 330 */
{ 2,	TD,	sys_pipe2,		NULL, "pipe2"				}, /* 331 */
{ 1,	TD,	sys_inotify_init1,	NULL, "inotify_init1"			}, /* 332 */
{ 5,	TD,	sys_preadv,		NULL, "preadv"				}, /* 333 */
{ 5,	TD,	sys_pwritev,		NULL, "pwritev"				}, /* 334 */
{ 4,	TP|TS,	sys_rt_tgsigqueueinfo,	NULL, "rt_tgsigqueueinfo"		}, /* 335 */
{ 5,	TD,	sys_perf_event_open,	NULL, "perf_event_open"			}, /* 336 */
{ 5,	TN,	sys_recvmmsg,		NULL, "recvmmsg"			}, /* 337 */
{ 2,	TD,	sys_fanotify_init,	NULL, "fanotify_init"			}, /* 338 */
{ 5,	TD|TF,	sys_fanotify_mark,	NULL, "fanotify_mark"			}, /* 339 */
{ 4,	0,	sys_prlimit64,		NULL, "prlimit64"			}, /* 340 */
{ 5,	TD|TF,	sys_name_to_handle_at,	NULL, "name_to_handle_at"		}, /* 341 */
{ 3,	TD,	sys_open_by_handle_at,	NULL, "open_by_handle_at"		}, /* 342 */
{ 2,	0,	sys_clock_adjtime,	NULL, "clock_adjtime"			}, /* 343 */
{ 1,	TD,	sys_syncfs,		NULL, "syncfs"				}, /* 344 */
{ 4,	TN,	sys_sendmmsg,		NULL, "sendmmsg"			}, /* 345 */
{ 2,	TD,	sys_setns,		NULL, "setns"				}, /* 346 */
{ 6,	0,	sys_process_vm_readv,	NULL, "process_vm_readv"		}, /* 347 */
{ 6,	0,	sys_process_vm_writev,	NULL, "process_vm_writev"		}, /* 348 */
{ 5,	0,	NULL,			NULL					}, /* 349 */
{ 5,	0,	NULL,			NULL					}, /* 350 */
{ 5,	0,	NULL,			NULL					}, /* 351 */
{ 5,	0,	NULL,			NULL					}, /* 352 */
{ 5,	0,	NULL,			NULL					}, /* 353 */
{ 5,	0,	NULL,			NULL					}, /* 354 */
{ 5,	0,	NULL,			NULL					}, /* 355 */
{ 5,	0,	NULL,			NULL					}, /* 356 */
{ 5,	0,	NULL,			NULL					}, /* 357 */
{ 5,	0,	NULL,			NULL					}, /* 358 */
{ 5,	0,	NULL,			NULL					}, /* 359 */
{ 5,	0,	NULL,			NULL					}, /* 360 */
{ 5,	0,	NULL,			NULL					}, /* 361 */
{ 5,	0,	NULL,			NULL					}, /* 362 */
{ 5,	0,	NULL,			NULL					}, /* 363 */
{ 5,	0,	NULL,			NULL					}, /* 364 */
{ 5,	0,	NULL,			NULL					}, /* 365 */
{ 5,	0,	NULL,			NULL					}, /* 366 */
{ 5,	0,	NULL,			NULL					}, /* 367 */
{ 5,	0,	NULL,			NULL					}, /* 368 */
{ 5,	0,	NULL,			NULL					}, /* 369 */
{ 5,	0,	NULL,			NULL					}, /* 370 */
{ 5,	0,	NULL,			NULL					}, /* 371 */
{ 5,	0,	NULL,			NULL					}, /* 372 */
{ 5,	0,	NULL,			NULL					}, /* 373 */
{ 5,	0,	NULL,			NULL					}, /* 374 */
{ 5,	0,	NULL,			NULL					}, /* 375 */
{ 5,	0,	NULL,			NULL					}, /* 376 */
{ 5,	0,	NULL,			NULL					}, /* 377 */
{ 5,	0,	NULL,			NULL					}, /* 378 */
{ 5,	0,	NULL,			NULL					}, /* 379 */
{ 5,	0,	NULL,			NULL					}, /* 380 */
{ 5,	0,	NULL,			NULL					}, /* 381 */
{ 5,	0,	NULL,			NULL					}, /* 382 */
{ 5,	0,	NULL,			NULL					}, /* 383 */
{ 5,	0,	NULL,			NULL					}, /* 384 */
{ 5,	0,	NULL,			NULL					}, /* 385 */
{ 5,	0,	NULL,			NULL					}, /* 386 */
{ 5,	0,	NULL,			NULL					}, /* 387 */
{ 5,	0,	NULL,			NULL					}, /* 388 */
{ 5,	0,	NULL,			NULL					}, /* 389 */
{ 5,	0,	NULL,			NULL					}, /* 390 */
{ 5,	0,	NULL,			NULL					}, /* 391 */
{ 5,	0,	NULL,			NULL					}, /* 392 */
{ 5,	0,	NULL,			NULL					}, /* 393 */
{ 5,	0,	NULL,			NULL					}, /* 394 */
{ 5,	0,	NULL,			NULL					}, /* 395 */
{ 5,	0,	NULL,			NULL					}, /* 396 */
{ 5,	0,	NULL,			NULL					}, /* 397 */
{ 5,	0,	NULL,			NULL					}, /* 398 */
{ 5,	0,	NULL,			NULL					}, /* 399 */

#if SYS_socket_subcall != 400
 #error fix me
#endif
{ 6,	0,	printargs,		NULL, "socket_subcall"			}, /* 400 */
{ 3,	TN,	sys_socket,		NULL, "socket"				}, /* 401 */
{ 3,	TN,	sys_bind,		NULL, "bind"				}, /* 402 */
{ 3,	TN,	sys_connect,		NULL, "connect"				}, /* 403 */
{ 2,	TN,	sys_listen,		NULL, "listen"				}, /* 404 */
{ 3,	TN,	sys_accept,		NULL, "accept"				}, /* 405 */
{ 3,	TN,	sys_getsockname,	NULL, "getsockname"			}, /* 406 */
{ 3,	TN,	sys_getpeername,	NULL, "getpeername"			}, /* 407 */
{ 4,	TN,	sys_socketpair,		NULL, "socketpair"			}, /* 408 */
{ 4,	TN,	sys_send,		NULL, "send",				}, /* 409 */
{ 4,	TN,	sys_recv,		NULL, "recv",				}, /* 410 */
{ 6,	TN,	sys_sendto,		NULL, "sendto",				}, /* 411 */
{ 6,	TN,	sys_recvfrom,		NULL, "recvfrom",			}, /* 412 */
{ 2,	TN,	sys_shutdown,		NULL, "shutdown"			}, /* 413 */
{ 5,	TN,	sys_setsockopt,		NULL, "setsockopt"			}, /* 414 */
{ 5,	TN,	sys_getsockopt,		NULL, "getsockopt"			}, /* 415 */
{ 3,	TN,	sys_sendmsg,		NULL, "sendmsg"				}, /* 416 */
{ 5,	TN,	sys_recvmsg,		NULL, "recvmsg"				}, /* 417 */
{ 4,	TN,	sys_accept4,		NULL, "accept4"				}, /* 418 */
{ 5,	TN,	sys_recvmmsg,		NULL, "recvmmsg"			}, /* 419 */

#if SYS_ipc_subcall != 420
 #error fix me
#endif

{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 420 */
{ 4,	TI,	sys_semop,		NULL, "semop"				}, /* 421 */
{ 4,	TI,	sys_semget,		NULL, "semget"				}, /* 422 */
{ 4,	TI,	sys_semctl,		NULL, "semctl"				}, /* 423 */
{ 5,	TI,	sys_semtimedop,		NULL, "semtimedop"			}, /* 424 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 425 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 426 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 427 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 428 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 429 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 430 */
{ 4,	TI,	sys_msgsnd,		NULL, "msgsnd"				}, /* 431 */
{ 4,	TI,	sys_msgrcv,		NULL, "msgrcv"				}, /* 432 */
{ 4,	TI,	sys_msgget,		NULL, "msgget"				}, /* 433 */
{ 4,	TI,	sys_msgctl,		NULL, "msgctl"				}, /* 434 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 435 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 436 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 437 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 438 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 439 */
{ 4,	0,	printargs,		NULL, "ipc_subcall"			}, /* 440 */
{ 4,	TI,	sys_shmat,		NULL, "shmat"				}, /* 441 */
{ 4,	TI,	sys_shmdt,		NULL, "shmdt"				}, /* 442 */
{ 4,	TI,	sys_shmget,		NULL, "shmget"				}, /* 443 */
{ 4,	TI,	sys_shmctl,		NULL, "shmctl"				}, /* 444 */
