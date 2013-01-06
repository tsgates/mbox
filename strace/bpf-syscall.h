#pragma once

static struct sock_filter filter[] = {
    LD_SYSCALL,
    TRACE_SYSCALL(open),
    TRACE_SYSCALL(openat),
    ALLOWED,
};
