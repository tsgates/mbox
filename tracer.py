#!/usr/bin/env python2

import os
import sys
import signals
import dbg

from ptrace   import *
from syscall  import *
from process  import *

def trace(args, handler):
    pinfo = {}
    pid = run(args)
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
            dbg.tracer("[%s] ptrace event: %s" % (pid, PTRACE_EVENTS[evt]))
        elif sig == (signals.SIGTRAP|0x80):
            handler(proc, proc.syscall())
        else:
            # deliver signal to child
            child_sig = sig
            dbg.tracer("[%s] signaled: %s" % (pid, signals.signame(sig)))

        ptrace_syscall(pid, child_sig)

# dump syscall
def dump_syscall(proc, sc):
    dbg.info(sc)
    
if __name__ == '__main__':
    trace(sys.argv[1:], dump_syscall)