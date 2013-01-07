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
    ALLOWED,
};
