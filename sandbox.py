#!/usr/bin/env python2

import os
import re
import dbg
import pprint
import chore
import osbox
import util

from sys      import stderr, exit
from optparse import OptionParser
from ptrace   import PtraceError

from ptrace.debugger import *
from ptrace.syscall  import *

from ptrace.error        import PTRACE_ERRORS
from ptrace.error        import writeError
from ptrace.func_call    import FunctionCallOptions
from ptrace.ctypes_tools import formatAddress

# main ptrace wrapper
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

        # add a flag not to be interactive
        if self.opts.interact:
            chore.interactive(self.os)

    def print_syscall(self, syscall):
        name = syscall.name
        text = syscall.format()

        if syscall.result is not None:
            text = "%-40s = %s" % (text, syscall.result_text)

        prefix = []
        prefix.append("[%s]" % syscall.process.pid)
        prefix.append(">" if syscall.is_enter() else "<")

        dbg.info(''.join(prefix) + ' ' + text)

    def loop(self, proc):
        # first query to break at next syscall
        proc.syscall()

        # loop until no process
        while self.debugger:
            # wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
                proc = event.process
            except ProcessExit, event:
                self.event_exit(event)
                continue
            except ProcessSignal, event:
                proc.syscall(event.signum)
                continue
            except NewProcessEvent, event:
                self.event_new_proc(event)
                continue
            except ProcessExecution, event:
                self.event_proc_exec(event)
                continue

            # process syscall enter or exit
            self.handle_syscall(proc)

    def handle_syscall(self, proc):
        syscall = proc.getSyscall(self.syscall_options)

        # print out system calls
        if self.opts.strace and syscall:
            self.print_syscall(syscall)

        # emulate os
        if not self.opts.no_sandbox:
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
        dbg.trace("*** %s ***" % event)

    def event_new_proc(self, event):
        process = event.process
        dbg.trace("*** New process %s ***" % process.pid)
        process.syscall()
        process.parent.syscall()

    def event_proc_exec(self, event):
        process = event.process
        dbg.trace("*** Process %s execution ***" % process.pid)
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
        self.os = osbox.OS(self.parse_root(self.opts.root, pid), os.getcwd())
        self.loop(proc)

    def fork(self, args, env=None):
        argv = [util.which(args[0])] + args[1:]
        return createChild(argv, False, env)

    def parse_root(self, path, pid):
        return path.replace("%PID", str(pid))

def print_syscalls(opts):
    pn = "syscall64.tbl"
    if not exists(pn):
        dbg.fatal("Failed to find %s" % pn)

    for l in open(pn):
        l = l.strip()
        if l.startswith("#") or len(l) == 0:
            continue

        # parsing syscall table
        toks = l.split()
        (num, abi, name) = toks[:3]
        entry = "N/A" if len(toks) < 4 else toks[3]

        # what we are keeping track of
        mark = "*" if name in SYSCALLS else " "
        print "%s% 3s: %s" % (mark, num, name)

def parse_args():
    parser = OptionParser(usage="%prog [options] -- program [arg1 arg2 ...]")
    parser.add_option("--list-syscalls", "-l",
                      help="Display system calls and exit",
                      action="store_true", default=None)
    parser.add_option("--strace", "-s",
                      help="Print out system calls",
                      action="store_true", default=False)
    parser.add_option("--no-sandbox", "-n",
                      help="No sandboxing",
                      action="store_true", default=False)
    parser.add_option("-r", "--root",
                      help="Root of the sandbox dir (ex /tmp/sandbox-%PID)",
                      default="/tmp/sandbox-%PID")
    parser.add_option("-q", "--quiet",
                      help="Quiet",
                      action="store_true", default=False)
    parser.add_option("-i", "--interact",
                      help="Interactivly checking modified files",
                      action="store_true", default=False)
    (opts, args) = parser.parse_args()

    # checking sanity
    if len(args) == 0 and not opts.list_syscalls:
        parser.print_help()
        exit(1)

    # control verbosity
    if opts.quiet:
        dbg.quiet(dbg, ["error"])

    return (opts, args)

if __name__ == "__main__":
    (opts, args) = parse_args()

    if opts.list_syscalls:
        print_syscalls(opts)
        exit(1)

    Sandbox(opts, args).run()