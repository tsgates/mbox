#!/usr/bin/env python2

import os
import re
import dbg

from sys      import stderr, exit
from optparse import OptionParser
from ptrace   import PtraceError

from ptrace.debugger import *
from ptrace.syscall  import *

from ptrace.error        import PTRACE_ERRORS
from ptrace.error        import writeError
from ptrace.func_call    import FunctionCallOptions
from ptrace.ctypes_tools import formatAddress

def is_syscall_exit(syscall):
    return syscall.result is not None

def is_syscall_enter(syscall):
    return not is_syscall_exit(syscall)

class Sandbox:
    def __init__(self, opts, args):
        self.opts = opts
        self.args = args

    def run(self):
        self.debugger = PtraceDebugger()
        try:
            self.run_debugger()
        except ProcessExit, event:
            self.event_exit(event)
        except PtraceError, err:
            dbg.fatal("ptrace() error: %s" % err)
        except KeyboardInterrupt:
            dbg.dbg.error("Interrupted.")
        except PTRACE_ERRORS, err:
            dbg.dbg.error("ptrace() error: %s" % err)
        self.debugger.quit()
        
    def print_syscall(self, syscall):
        name = syscall.name
        text = syscall.format()
        
        if syscall.result is not None:
            text = "%-40s = %s" % (text, syscall.result_text)
            
        prefix = []
        prefix.append("[%s]" % syscall.process.pid)
        prefix.append(">" if is_syscall_enter(syscall) else "<")
        
        dbg.info(''.join(prefix) + ' ' + text)

    def loop(self, process):
        # first query to break at next syscall
        process.syscall()

        # loop until no process
        while self.debugger:
            # wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
                process = event.process
            except ProcessExit, event:
                self.event_exit(event)
                continue
            except ProcessSignal, event:
                event.display()
                process.syscall(event.signum)
                continue
            except NewProcessEvent, event:
                self.event_new_proc(event)
                continue
            except ProcessExecution, event:
                self.event_proc_exec(event)
                continue

            # process syscall enter or exit
            self.handle_syscall(process)

    def handle_syscall(self, process):
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        if syscall:
            self.print_syscall(syscall)
        # break at next syscall
        process.syscall()

    def event_exit(self, event):
        # display syscall which has not exited
        state = event.process.syscall_state
        if (state.next_event == "exit") \
          and (not True) \
          and state.syscall:
            self.print_syscall(state.syscall)

        # display exit message
        dbg.error("*** %s ***" % event)

    def event_new_proc(self, event):
        process = event.process
        dbg.error("*** New process %s ***" % process.pid)
        process.syscall()
        process.parent.syscall()

    def event_proc_exec(self, event):
        process = event.process
        dbg.error("*** Process %s execution ***" % process.pid)
        process.syscall()

    def run_proc(self, args):
        pid = self.fork(args)
        try:
            proc = self.debugger.addProcess(pid, is_attached=True)
        except PtraceError as e:
            if e.errno == EPERM:
                fatal("No permission: %s" % str(e))
            fatal("Can't be attached: pid=%s" % pid)
        except ChildError as e:
            fatal("Can't be attached: %s" % str(e))
        return (pid, proc)

    def run_debugger(self):
        try:
            self.debugger.traceFork()
            self.debugger.traceExec()
        except DebuggerError:
            dbg.fatal("OS doesn't support to trace fork(), exec()")

        (pid, proc) = self.run_proc(self.args)
            
        self.syscall_options = FunctionCallOptions(
            write_types=False,
            write_argname=False,
            string_max_length=60,
            replace_socketcall=False,
            write_address=False,
            max_array_count=300,
        )
        self.syscall_options.instr_pointer = False
        
        self.loop(proc)

    def fork(self, args, env=None):
        return createChild(args, False, env)

def print_syscalls():
    syscalls = SYSCALL_NAMES.items()
    syscalls.sort(key=lambda data: data[0])
    for num, name in syscalls:
        print "% 3s: %s" % (num, name)
    
def parse_args():
    parser = OptionParser(usage="%prog [options] -- program [arg1 arg2 ...]")
    parser.add_option("--list-syscalls",
                      help="Display system calls and exit",
                      action="store_true", default=False)
    (opts, args) = parser.parse_args()

    # checking sanity
    if len(args) == 0:
        parser.print_help()
        exit(1)

    return (opts, args)

if __name__ == "__main__":
    (opts, args) = parse_args()

    if opts.list_syscalls:
        print_syscalls()
        exit(1)
    
    Sandbox(opts, args).run()