#pragma once

static struct sock_filter filter[] = {
    LD_SYSCALL,
    TRACE_SYSCALL(open),
    TRACE_SYSCALL(openat),
    TRACE_SYSCALL(stat),
    TRACE_SYSCALL(lstat),
    TRACE_SYSCALL(newfstatat),
    TRACE_SYSCALL(mkdir),
    TRACE_SYSCALL(mkdirat),
    TRACE_SYSCALL(rmdir),
    TRACE_SYSCALL(unlink),
    TRACE_SYSCALL(unlinkat),
    TRACE_SYSCALL(access),
    TRACE_SYSCALL(faccessat),
    TRACE_SYSCALL(getdents),
    ALLOWED,
};
