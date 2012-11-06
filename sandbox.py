#!/usr/bin/env python2

import os
import re
import dbg
import pprint
import collections

from sys      import stderr, exit
from optparse import OptionParser
from ptrace   import PtraceError

from ptrace.debugger import *
from ptrace.syscall  import *

from ptrace.error        import PTRACE_ERRORS
from ptrace.error        import writeError
from ptrace.func_call    import FunctionCallOptions
from ptrace.ctypes_tools import formatAddress

from spec import *

class OS:
    def __init__(self, root, cwd):
        self.root = root
        self.cwd  = cwd
        self.stat = collections.defaultdict(int)
        self.fds  = {0: "stdin",
                     1: "stdout",
                     2: "stderr"}

    def run(self, proc, syscall):
        if syscall.is_enter():
            self.stat[syscall.name] += 1

        cond = "enter" if syscall.is_enter() else "exit"
        func = "%s_%s" % (syscall.name, cond)
        if hasattr(self, func):
            getattr(self, func)(proc, Syscall(syscall))

    def open_enter(self, proc, sc):
        dbg.ns(sc)
        dbg.ns(" -> %s" % (sc.path.chroot(self.root, self.cwd)))
        
        # XXX. if mode

    def open_exit(self, proc, sc):
        fd = sc.ret
        pn = sc.path
        self.fds[fd.int()] = pn
        dbg.ns(sc)
        
    def openat_enter(self, proc, sc):
        dbg.ns(sc)
        dbg.ns(" -> %s" % (sc.path.chroot(self.root, self.cwd)))

    def openat_exit(self, proc, sc):
        print sc

    def close_enter(self, proc, sc):
        pass

    def close_exit(self, proc, sc):
        self.fds[sc.fd.int()] = None
    
    def done(self):
        for (n, v) in self.stat.items():
            print "%15s: %3s" % (n, v)
        pprint.pprint(self.fds)
        
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
            dbg.error("Interrupted.")
        self.debugger.quit()
        self.os.done()
        
    def print_syscall(self, syscall):
        name = syscall.name
        text = syscall.format()
        
        if syscall.result is not None:
            text = "%-40s = %s" % (text, syscall.result_text)
            
        prefix = []
        prefix.append("[%s]" % syscall.process.pid)
        prefix.append(">" if syscall.is_enter() else "<")
        
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

    def handle_syscall(self, proc):
        syscall = proc.getSyscall(self.syscall_options)

        # print out system calls
        if self.opts.strace and syscall:
            self.print_syscall(syscall)

        # emulate os
        self.os.run(proc, syscall)

        # break at next syscall
        proc.syscall()

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
        # set ptrace flags
        try:
            self.debugger.traceFork()
            self.debugger.traceExec()
            self.debugger.enableSysgood()
        except DebuggerError:
            dbg.fatal("OS doesn't support to trace fork(), exec()")

        (pid, proc) = self.run_proc(self.args)

        # for strace format
        self.syscall_options = FunctionCallOptions(
            write_types=False,
            write_argname=False,
            string_max_length=60,
            replace_socketcall=False,
            write_address=False,
            max_array_count=300,
        )
        self.syscall_options.instr_pointer = False

        # init os instance
        self.os = OS(self.parse_root(self.opts.root, pid), os.getcwd())
        self.loop(proc)

    def fork(self, args, env=None):
        return createChild(args, False, env)

    def parse_root(self, path, pid):
        return path.replace("%PID", str(pid))

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
    parser.add_option("--strace", "-s",
                      help="Print out system calls",
                      action="store_true", default=False)
    parser.add_option("-r", "--root",
                      help="Root of the sandbox dir (ex /tmp/sandbox-%PID)",
                      default="/tmp/sandbox-%PID")
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