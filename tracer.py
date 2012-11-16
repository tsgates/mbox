#!/usr/bin/env python2

import os
import sys
import signal

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
            print "> new pid: %s" % pid
            pinfo[pid] = Process(pid)

        proc = pinfo[pid]
        
        if os.WIFEXITED(status):
            code = os.WEXITSTATUS(status)
            del pinfo[pid]
            continue

        if os.WIFSIGNALED(status):
            code = os.WTERMSIG(status)
            del pinfo[pid]
            continue

        sig = os.WSTOPSIG(status)
        evt = status >> 16
        if sig == signal.SIGTRAP and evt != 0:
            print "> event: %s" % PTRACE_EVENTS[evt]

        if evt == 0:
            handler(proc, proc.syscall())
            
        ptrace_syscall(pid)

if __name__ == '__main__':
    # dump syscall
    def handler(proc, sc):
        print sc
    
    trace(sys.argv[1:], handler)