from ptrace.ctypes_tools import formatAddress
from ptrace import PtraceError
from logging import info
from weakref import ref
from ptrace.cpu_info import CPU_POWERPC, CPU_WORD_SIZE
from ptrace.ctypes_tools import word2bytes
from ptrace.six import b

class Breakpoint(object):
    """
    Software breakpoint.

    Use desinstall() method to remove the breakpoint from the process.
    """
    def __init__(self, process, address, size=None):
        self._installed = False
        self.process = ref(process)
        self.address = address
        if CPU_POWERPC:
            size = CPU_WORD_SIZE
        elif size is None:
            size = 1
        self.size = size

        # Store instruction bytes
        info("Install %s" % self)
        self.old_bytes = process.readBytes(address, size)

        if CPU_POWERPC:
            # Replace instruction with "TRAP"
            new_bytes = word2bytes(0x0cc00000)
        else:
            # Replace instruction with "INT 3"
            new_bytes = b("\xCC") * size
        process.writeBytes(address, new_bytes)
        self._installed = True

    def desinstall(self, set_ip=False):
        """
        Remove the breakpoint from the associated process. If set_ip is True,
        restore the instruction pointer to the address of the breakpoint.
        """
        if not self._installed:
            return
        self._installed = False
        info("Desinstall %s" % self)
        process = self.process()
        if not process:
            return
        if process.running:
            process.writeBytes(self.address, self.old_bytes)
        if set_ip:
            process.setInstrPointer(self.address)
        process.removeBreakpoint(self)

    def __str__(self):
        return "<Breakpoint %s..%s>" % (
            formatAddress(self.address),
            formatAddress(self.address + self.size - 1))

    def __del__(self):
        try:
            self.desinstall(False)
        except PtraceError:
            pass

