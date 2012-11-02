#!/usr/bin/env python
"""
Here is a tool which I have been using to debug libc startup code where I
didn't find gdb very helpful. It single steps the process and prints each
instruction pointer address. To go faster, it allows a number of syscalls to
run before starting single-stepping.

It's possible to pipe the addresses through addr2line to get a very
simple tracing debugger. :-)

I couldn't see a way to catch syscalls and single step at the same
time.  As a consequence the tool can't handle multiple threads.

Mark
"""

import signal
from ptrace.debugger import ProcessExit, ProcessSignal
import strace

class Tracer(strace.SyscallTracer):
    def createCommonOptions(self, parser):
        parser.add_option(
            "-n", dest="syscall_limit", type="int", default=None,
            help="Number of syscalls before switching to single step")
        super(Tracer, self).createCommonOptions(parser)

    def syscallTrace(self, process):
        syscall_limit = self.options.syscall_limit
        i = 0
        while i < syscall_limit or syscall_limit is None:
            print i
            i += 1
            process.syscall()
            self.debugger.waitSyscall()
        i = 0
        while self.debugger:
            eip = process.getInstrPointer()
            print i, process.pid, "[%08x]" % eip
            i += 1
            process.singleStep()
            event = self.debugger.waitProcessEvent()
            if isinstance(event, ProcessExit):
                print "process exit"
                return
            if (isinstance(event, ProcessSignal) and
                event.signum & ~128 != signal.SIGTRAP):
                print "died with signal %i" % event.signum
                return

if __name__ == "__main__":
    Tracer().main()

