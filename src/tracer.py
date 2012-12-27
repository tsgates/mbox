#!/usr/bin/env python2

import os
import sys
import signals
import dbg

from ptrace   import *
from syscall  import *
from process  import *

def trace(opt, args, handler):
    pinfo = {}
    pid = run(opt, args)
    pinfo[pid] = Process(pid)

    while len(pinfo) != 0:
        (pid, status, res) = os.wait4(-1, WALL)

        if not pid in pinfo:
            dbg.tracer("new pid: %s" % pid)
            pinfo[pid] = Process(pid, True)
        
        proc = pinfo[pid]
        
        if os.WIFEXITED(status):
            code = os.WEXITSTATUS(status)
            del pinfo[pid]
            dbg.tracer("[%s] exited code=%s" % (pid, code))
            continue

        if os.WIFSIGNALED(status):
            code = os.WTERMSIG(status)
            del pinfo[pid]
            dbg.tracer("[%s] killed by code=%s" % (pid, code))
            continue

        sig = os.WSTOPSIG(status)
        evt = status >> 16
        child_sig = 0

        if sig == signals.SIGSTOP and proc.state == PS_IGNSTOP:
            dbg.tracer("ignored: %s" % proc.pid)
            proc.set_ptrace_flags_done()
        elif sig == signals.SIGTRAP and evt != 0:
            # if using seccomp
            if opt == TRACE_SECCOMP and evt == PTRACE_EVENT_SECCOMP:
                # NOTE. only entered syscall in case of using seccomp.
                handler(proc, proc.syscall())
                # stop at the exit of the current syscall
                ptrace_syscall(pid, child_sig)
                continue
            else:
                dbg.tracer("[%s] ptrace event: %s" % (pid, PTRACE_EVENTS[evt]))
        elif sig == (signals.SIGTRAP|0x80):
            # NOTE. handle the current trap, but unfortunately we shoul guess
            # the state of tracee's syscalls, whether exit or enter. In case of
            # ptrace, we constantly invoke handle() this place, but in case of
            # seccomp, only exited syscalls will de handled here.
            handler(proc, proc.syscall())
        else:
            # deliver signal to child
            child_sig = sig
            dbg.tracer("[%s] signaled: %s" % (pid, signals.signame(sig)))

        # interpose on next syscall
        if opt == TRACE_SECCOMP:
            ptrace_cont(pid, child_sig)
        elif opt == TRACE_PTRACE:
            ptrace_syscall(pid, child_sig)

# dump syscall
def dump_syscall(proc, sc):
    dbg.info(sc)
    
if __name__ == '__main__':
    trace(sys.argv[1:], dump_syscall)