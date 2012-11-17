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
            dbg.tracer("[%s] killed by code=%s" % (pid, code))
            continue

        sig = os.WSTOPSIG(status)
        evt = status >> 16
        if sig == signals.SIGTRAP and evt != 0:
            dbg.tracer("[%s] ptrace event: %s" % (pid, PTRACE_EVENTS[evt]))
            if evt == PTRACE_EVENT_CLONE:
                print pinfo
                newpid = ptrace_geteventmsg(pid)
                dbg.tracer("XXX: %s" % newpid)
                ptrace_attach(newpid)
                ptrace(PTRACE_SETOPTIONS, newpid, 0,
                       PTRACE_O_TRACESYSGOOD    # SIGTRAP|0x80 if syscall call traps
                       | PTRACE_O_TRACEFORK     # PTRACE_EVENT_FORK
                       | PTRACE_O_TRACEVFORK    # PTRACE_EVENT_VFORK
                       | PTRACE_O_TRACECLONE    # PTRACE_EVENT_CLONE
                       | PTRACE_O_TRACEEXEC     # PTRACE_EVENT_EXEC
                       | PTRACE_O_TRACEEXIT)    # PTRACE_EVENT_EXIT
                ptrace(PTRACE_CONT, newpid, 0, 0)
                (pid, status) = os.waitpid(newpid, 0)
                
        elif sig == (signals.SIGTRAP|0x80):
            handler(proc, proc.syscall())
        else:
            dbg.tracer("[%s] signaled: %s" % (pid, signals.signame(sig)))

        ptrace_syscall(pid)

# dump syscall
def dump_syscall(proc, sc):
    dbg.info(sc)
    
if __name__ == '__main__':
    trace(sys.argv[1:], dump_syscall)