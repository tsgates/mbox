#!/usr/bin/env python2

import os
import sys
import signal
import dbg

from ptrace   import *
from syscall  import *
from process  import *

def trace(args, handler):
    pinfo = {}
    pid = run(args)
    pinfo[pid] = Process(pid)

    while len(pinfo) != 0:
        (pid, status) = os.wait()

        if not pid in pinfo:
            dbg.tracer("new pid: %s" % pid)
            pinfo[pid] = Process(pid)

        proc = pinfo[pid]
        
        if os.WIFEXITED(status):
            code = os.WEXITSTATUS(status)
            del pinfo[pid]
            dbg.tracer("[%s] exited code=%s" % (pid, code))
            continue

        if os.WIFSIGNALED(status):
            code = os.WTERMSIG(status)
            del pinfo[pid]
            dbg.tracer("[%s] signal: code=%s" % (pid, code))
            continue

        sig = os.WSTOPSIG(status)
        evt = status >> 16
        if sig == signal.SIGTRAP and evt != 0:
            dbg.tracer("[%s] ptrace event: %s" % (pid, PTRACE_EVENTS[evt]))

        if evt == 0:
            handler(proc, proc.syscall())
            
        ptrace_syscall(pid)

# dump syscall
def dump_syscall(proc, sc):
    print sc
    
if __name__ == '__main__':
    trace(sys.argv[1:], dump_syscall)