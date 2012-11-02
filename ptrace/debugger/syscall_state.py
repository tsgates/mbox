from ptrace.syscall import PtraceSyscall
from signal import SIGTRAP

class SyscallState(object):
    def __init__(self, process):
        self.process = process
        self.ignore_exec_trap = True
        self.ignore_callback = None
        self.clear()

    def event(self, options):
        if self.next_event == "exit":
            return self.exit()
        else:
            return self.enter(options)

    def enter(self, options):
        # syscall enter
        regs = self.process.getregs()
        self.syscall = PtraceSyscall(self.process, options, regs)
        self.name = self.syscall.name
        if (not self.ignore_callback) \
        or (not self.ignore_callback(self.syscall)):
            self.syscall.enter(regs)
        else:
            self.syscall = None
        self.next_event = "exit"
        return self.syscall

    def exit(self):
        if self.syscall:
            self.syscall.exit()
        if self.ignore_exec_trap \
        and self.name == "execve" \
        and not self.process.debugger.trace_exec:
            # Ignore the SIGTRAP after exec() syscall exit
            self.process.syscall()
            self.process.waitSignals(SIGTRAP)
        syscall = self.syscall
        self.clear()
        return syscall

    def clear(self):
        self.syscall = None
        self.name = None
        self.next_event = "enter"

