#!/usr/bin/env python
from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, Application,
    ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.syscall import (SYSCALL_NAMES, SYSCALL_PROTOTYPES,
    FILENAME_ARGUMENTS, SOCKET_SYSCALL_NAMES)
from ptrace.func_call import FunctionCallOptions
from sys import stderr, exit
from optparse import OptionParser
from logging import getLogger, error
from ptrace.syscall.socketcall_constants import SOCKETCALL
from ptrace.compatibility import any
from ptrace.error import PTRACE_ERRORS, writeError
from ptrace.ctypes_tools import formatAddress
import re

class SyscallTracer(Application):
    def __init__(self):
        Application.__init__(self)

        # Parse self.options
        self.parseOptions()

        # Setup output (log)
        self.setupLog()

    def setupLog(self):
        if self.options.output:
            fd = open(self.options.output, 'w')
        else:
            fd = stderr
        self._setupLog(fd)

    def parseOptions(self):
        parser = OptionParser(usage="%prog [options] -- program [arg1 arg2 ...]")
        self.createCommonOptions(parser)
        parser.add_option("--enter", help="Show system call enter and exit",
            action="store_true", default=False)
        parser.add_option("--profiler", help="Use profiler",
            action="store_true", default=False)
        parser.add_option("--type", help="Display arguments type and result type (default: no)",
            action="store_true", default=False)
        parser.add_option("--name", help="Display argument name (default: no)",
            action="store_true", default=False)
        parser.add_option("--string-length", "-s", help="String max length (default: 300)",
            type="int", default=300)
        parser.add_option("--array-count", help="Maximum number of array items (default: 20)",
            type="int", default=20)
        parser.add_option("--raw-socketcall", help="Raw socketcall form",
            action="store_true", default=False)
        parser.add_option("--output", "-o", help="Write output to specified log file",
            type="str")
        parser.add_option("--ignore-regex", help="Regex used to filter syscall names (eg. --ignore='^(gettimeofday|futex|f?stat)')",
            type="str")
        parser.add_option("--address", help="Display structure addressl",
            action="store_true", default=False)
        parser.add_option("--syscalls", '-e', help="Comma separated list of shown system calls (other will be skipped)",
            type="str", default=None)
        parser.add_option("--socket", help="Show only socket functions",
            action="store_true", default=False)
        parser.add_option("--filename", help="Show only syscall using filename",
            action="store_true", default=False)
        parser.add_option("--show-pid",
            help="Prefix line with process identifier",
            action="store_true", default=False)
        parser.add_option("--list-syscalls",
            help="Display system calls and exit",
            action="store_true", default=False)
        parser.add_option("-i", "--show-ip",
            help="print instruction pointer at time of syscall",
            action="store_true", default=False)

        self.createLogOptions(parser)

        self.options, self.program = parser.parse_args()

        if self.options.list_syscalls:
            syscalls = SYSCALL_NAMES.items()
            syscalls.sort(key=lambda data: data[0])
            for num, name in syscalls:
                print "% 3s: %s" % (num, name)
            exit(0)

        if self.options.pid is None and not self.program:
            parser.print_help()
            exit(1)

        # Create "only" filter
        only = set()
        if self.options.syscalls:
            # split by "," and remove spaces
            for item in self.options.syscalls.split(","):
                item = item.strip()
                if not item or item in only:
                    continue
                ok = True
                valid_names = SYSCALL_NAMES.values()
                for name in only:
                    if name not in valid_names:
                        print >>stderr, "ERROR: unknow syscall %r" % name
                        ok = False
                if not ok:
                    print >>stderr
                    print >>stderr, "Use --list-syscalls options to get system calls list"
                    exit(1)
                # remove duplicates
                only.add(item)
        if self.options.filename:
            for syscall, format in SYSCALL_PROTOTYPES.iteritems():
                restype, arguments = format
                if any(argname in FILENAME_ARGUMENTS for argtype, argname in arguments):
                    only.add(syscall)
        if self.options.socket:
            only |= SOCKET_SYSCALL_NAMES
        self.only = only
        if self.options.ignore_regex:
            try:
                self.ignore_regex = re.compile(self.options.ignore_regex)
            except Exception, err:
                print "Invalid regular expression! %s" % err
                print "(regex: %r)" % self.options.ignore_regex
                exit(1)
        else:
            self.ignore_regex = None

        if self.options.fork:
            self.options.show_pid = True

        self.processOptions()

    def ignoreSyscall(self, syscall):
        name = syscall.name
        if self.only and (name not in self.only):
            return True
        if self.ignore_regex and self.ignore_regex.match(name):
            return True
        return False

    def displaySyscall(self, syscall):
        name = syscall.name
        text = syscall.format()
        if syscall.result is not None:
            text = "%-40s = %s" % (text, syscall.result_text)
        prefix = []
        if self.options.show_pid:
            prefix.append("[%s]" % syscall.process.pid)
        if self.options.show_ip:
            prefix.append("[%s]" % formatAddress(syscall.instr_pointer))
        if prefix:
            text = ''.join(prefix) + ' ' + text
        error(text)

    def syscallTrace(self, process):
        # First query to break at next syscall
        self.prepareProcess(process)

        while True:
            # No more process? Exit
            if not self.debugger:
                break

            # Wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
                process = event.process
            except ProcessExit, event:
                self.processExited(event)
                continue
            except ProcessSignal, event:
                event.display()
                process.syscall(event.signum)
                continue
            except NewProcessEvent, event:
                self.newProcess(event)
                continue
            except ProcessExecution, event:
                self.processExecution(event)
                continue

            # Process syscall enter or exit
            self.syscall(process)

    def syscall(self, process):
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        if syscall and (syscall.result is not None or self.options.enter):
            self.displaySyscall(syscall)

        # Break at next syscall
        process.syscall()

    def processExited(self, event):
        # Display syscall which has not exited
        state = event.process.syscall_state
        if (state.next_event == "exit") \
        and (not self.options.enter) \
        and state.syscall:
            self.displaySyscall(state.syscall)

        # Display exit message
        error("*** %s ***" % event)

    def prepareProcess(self, process):
        process.syscall()
        process.syscall_state.ignore_callback = self.ignoreSyscall

    def newProcess(self, event):
        process = event.process
        error("*** New process %s ***" % process.pid)
        self.prepareProcess(process)
        process.parent.syscall()

    def processExecution(self, event):
        process = event.process
        error("*** Process %s execution ***" % process.pid)
        process.syscall()

    def runDebugger(self):
        # Create debugger and traced process
        self.setupDebugger()
        process = self.createProcess()
        if not process:
            return

        self.syscall_options = FunctionCallOptions(
            write_types=self.options.type,
            write_argname=self.options.name,
            string_max_length=self.options.string_length,
            replace_socketcall=not self.options.raw_socketcall,
            write_address=self.options.address,
            max_array_count=self.options.array_count,
        )
        self.syscall_options.instr_pointer = self.options.show_ip

        self.syscallTrace(process)

    def main(self):
        if self.options.profiler:
            from ptrace.profiler import runProfiler
            runProfiler(getLogger(), self._main)
        else:
            self._main()

    def _main(self):
        self.debugger = PtraceDebugger()
        try:
            self.runDebugger()
        except ProcessExit, event:
            self.processExited(event)
        except PtraceError, err:
            error("ptrace() error: %s" % err)
        except KeyboardInterrupt:
            error("Interrupted.")
        except PTRACE_ERRORS, err:
            writeError(getLogger(), err, "Debugger error")
        self.debugger.quit()

    def createChild(self, program):
        pid = Application.createChild(self, program)
        error("execve(%s, %s, [/* 40 vars */]) = %s" % (
            program[0], program, pid))
        return pid

if __name__ == "__main__":
    SyscallTracer().main()

