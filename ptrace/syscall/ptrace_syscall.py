from os import strerror
from itertools import izip
from ptrace.cpu_info import CPU_X86_64, CPU_POWERPC, CPU_I386
from ptrace.ctypes_tools import ulong2long, formatAddress, formatWordHex
from ptrace.func_call import FunctionCall
from ptrace.syscall import SYSCALL_NAMES, SYSCALL_PROTOTYPES, SyscallArgument
from ptrace.syscall.socketcall import setupSocketCall
from ptrace.os_tools import RUNNING_LINUX, RUNNING_BSD
from ptrace.cpu_info import CPU_WORD_SIZE
from ptrace.binding.cpu import CPU_INSTR_POINTER

PREFORMAT_ARGUMENTS = {
    "select": (2, 3, 4),
    "execve": (0, 1, 2),
    "clone": (0, 1),
}

class PtraceSyscall(FunctionCall):
    def __init__(self, process, options, regs=None):
        FunctionCall.__init__(self, "syscall", options, SyscallArgument)
        self.process = process
        self.restype = "long"
        self.result = None
        self.result_text = None
        self.instr_pointer = None
        if not regs:
            regs = self.process.getregs()
        self.readSyscall(regs)

    def enter(self, regs=None):
        if not regs:
            regs = self.process.getregs()
        argument_values = self.readArgumentValues(regs)
        self.readArguments(argument_values)

        if self.name == "socketcall" and self.options.replace_socketcall:
            setupSocketCall(self, self.process, self[0], self[1].value)

        # Some arguments are lost after the syscall, so format them now
        if self.name in PREFORMAT_ARGUMENTS:
            for index in PREFORMAT_ARGUMENTS[self.name]:
                argument = self.arguments[index]
                argument.format()

        if self.options.instr_pointer:
            self.instr_pointer = getattr(regs, CPU_INSTR_POINTER)

    def readSyscall(self, regs):
        # Read syscall number
        if CPU_POWERPC:
            self.syscall = regs.gpr0
        elif RUNNING_LINUX:
            if CPU_X86_64:
                self.syscall = regs.orig_rax
            else:
                self.syscall = regs.orig_eax
        else:
            self.syscall = regs.eax

        # Get syscall variables
        self.name = SYSCALL_NAMES.get(self.syscall, "syscall<%s>" % self.syscall)

    def readArgumentValues(self, regs):
        if RUNNING_BSD:
            sp = self.process.getStackPointer()
            return [ self.process.readWord(sp + index*CPU_WORD_SIZE)
                for index in xrange(1, 6+1) ]
        if CPU_I386:
            return (regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.ebp)
        if CPU_X86_64:
            return (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9)
        if CPU_POWERPC:
            return (regs.gpr3, regs.gpr4, regs.gpr5, regs.gpr6, regs.gpr7, regs.gpr8)
        raise NotImplementedError()

    def readArguments(self, argument_values):
        if self.name in SYSCALL_PROTOTYPES:
            self.restype, formats = SYSCALL_PROTOTYPES[self.name]
            for value, format in izip(argument_values, formats):
                argtype, argname = format
                self.addArgument(value=value, name=argname, type=argtype)
        else:
            for value in argument_values:
                self.addArgument(value=value)

    def exit(self):
        if self.name in PREFORMAT_ARGUMENTS:
            preformat = set(PREFORMAT_ARGUMENTS[self.name])
        else:
            preformat = set()

        # Data pointed by arguments may have changed during the syscall
        # eg. uname() syscall
        for index, argument in enumerate(self.arguments):
            if index in preformat:
                # Don't lose preformatted arguments
                continue
            if argument.type and not argument.type.endswith("*"):
                continue
            argument.text = None

        if CPU_I386:
            regname = "eax"
        elif CPU_X86_64:
            regname = "rax"
        elif CPU_POWERPC:
            regname = "result"
        else:
            raise NotImplementedError()
        self.result = self.process.getreg(regname)

        if self.restype.endswith("*"):
            text = formatAddress(self.result)
        else:
            uresult = self.result
            self.result = ulong2long(self.result)
            if self.result < 0:
                text = "%s (%s)" % (
                    self.result, strerror(-self.result))
            elif not(0 <= self.result <= 9):
                text = "%s (%s)" % (self.result, formatWordHex(uresult))
            else:
                text = str(self.result)
        self.result_text = text
        return text

    def __str__(self):
        return "<Syscall name=%r>" % self.name

