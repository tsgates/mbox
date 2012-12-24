#ifndef _SECCOMP_BPF_H_
#define _SECCOMP_BPF_H_

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define OFF_SYSCALL     (offsetof(struct seccomp_data, nr  ))
#define OFF_ARCH        (offsetof(struct seccomp_data, arch))

#define LD_SYSCALL                                      \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, OFF_SYSCALL)

#define TRACE_SYSCALL(name)                             \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)

#define ALLOWED                                         \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#endif
