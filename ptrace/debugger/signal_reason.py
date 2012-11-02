from ptrace.ctypes_tools import formatAddress, formatWordHex
from ptrace.error import PtraceError
from ptrace.cpu_info import CPU_I386, CPU_X86_64
from ptrace.process_tools import formatProcessStatus
import re

# Find all Intel registers (in upper case)
if CPU_I386:
    regex = 'E[A-Z]{2}|[CDEFGS]S|[ABCD]L'
elif CPU_X86_64:
    regex = '[ER][A-Z]{2}|[CDEFGS]S|[ABCD]L'
else:
    regex = None
if regex:
    REGISTER_REGEX = re.compile(r'\b(?:%s)\b' % regex)
else:
    REGISTER_REGEX = None

def extractRegisters(process, instr):
    registers = {}
    if not process or not instr or not REGISTER_REGEX:
        return registers
    asm = instr.text
    asm = asm.upper()
    # Skip the operator ("MOV CL, [EAX]" => "CL, [EAX]")
    asm = asm.split(" ", 1)[1]
    for match in REGISTER_REGEX.finditer(asm):
        name = match.group(0)
        name = name.lower()
        try:
            value = process.getreg(name)
            registers[name] = value
        except PtraceError, err:
            pass
    return registers

def findMappings(addresses, process, size):
    mappings = []
    if addresses is None or not process:
        return mappings
    if not isinstance(addresses, (list, tuple)):
        addresses = (addresses,)
    if not size:
        size = 0
    process_mappings = process.readMappings()
    if not process_mappings:
        return mappings
    for address in addresses:
        address_str = formatAddress(address)
        if 1 < size:
            address_str += "..%s" % formatAddress(address + size - 1)
        found = False
        for map in process_mappings:
            if (map.start <= address < map.end) \
            or (map.start <= (address + size - 1) < map.end):
                found = True
                mappings.append("%s is part of %s" % (address_str, map))
        if not found:
            mappings.append("%s is not mapped in memory" % address_str)
    return mappings

class SignalInfo(Exception):
    def __init__(self, name, text,
    address=None, size=None, instr=None,
    process=None, registers=None):
        Exception.__init__(self, text)
        self.name = name
        self.text = text
        self.instr = instr
        self.registers = extractRegisters(process, instr)
        if registers:
            self.registers.update(registers)
        self.mappings = findMappings(address, process, size)

    def display(self, log):
        log(self.text)
        self.displayExtra(log)
        if self.instr:
            log("- instruction: %s" % self.instr)
        for mapping in self.mappings:
            log("- mapping: %s" % mapping)
        for name, value in self.registers.iteritems():
            log("- register %s=%s" % (name, formatWordHex(value)))

    def displayExtra(self, log):
        pass

class DivisionByZero(SignalInfo):
    def __init__(self, instr=None, process=None):
        SignalInfo.__init__(self, "div_by_zero",
            "Division by zero", instr=instr, process=process)

class Abort(SignalInfo):
    def __init__(self):
        SignalInfo.__init__(self, "abort",
            "Program received signal SIGABRT, Aborted.")

class StackOverflow(SignalInfo):
    def __init__(self, stack_ptr, stack_map, instr=None, process=None):
        text = "STACK OVERFLOW! Stack pointer is in %s" % stack_map
        SignalInfo.__init__(self, "stack_overflow", text,
            address=stack_ptr, registers={'<stack ptr>': stack_ptr},
            instr=instr, process=process)
        self.stack_ptr = stack_ptr
        self.stack_map = stack_map

class InvalidMemoryAcces(SignalInfo):
    NAME = "invalid_mem_access"
    PREFIX = "Invalid memory access"
    PREFIX_ADDR = "Invalid memory access to %s"

    def __init__(self, address=None, size=None, instr=None, registers=None, process=None):
        """
        address is an integer or a list of integer
        """
        if address is not None:
            if isinstance(address, (list, tuple)):
                arguments = " or ".join( formatAddress(addr) for addr in address )
            else:
                arguments = formatAddress(address)
            message = self.PREFIX_ADDR % arguments
        else:
            message = self.PREFIX
        if size:
            message += " (size=%s bytes)" % size
        name = self.NAME
        if address is not None:
            name += "-" + formatAddress(address).lower()
        SignalInfo.__init__(self, name, message,
            address=address, size=size, instr=instr,
            process=process, registers=registers)

class InvalidRead(InvalidMemoryAcces):
    NAME = "invalid_read"
    PREFIX = "Invalid read"
    PREFIX_ADDR = "Invalid read from %s"

class InvalidWrite(InvalidMemoryAcces):
    NAME = "invalid_write"
    PREFIX = "Invalid write"
    PREFIX_ADDR = "Invalid write to %s"

class InstructionError(SignalInfo):
    def __init__(self, address, process=None):
        SignalInfo.__init__(self, "instr_error",
            "UNABLE TO EXECUTE CODE AT %s (SEGMENTATION FAULT)" % formatAddress(address),
            address=address,
            process=process,
            registers={'<instr pointer>': address})

class ChildExit(SignalInfo):
    def __init__(self, pid=None, status=None, uid=None):
        if pid is not None and status is not None:
            message = formatProcessStatus(status, "Child process %s" % pid)
        else:
            message = "Child process exited"
        SignalInfo.__init__(self, "child_exit", message)
        self.pid = pid
        self.status = status
        self.uid = uid

    def displayExtra(self, log):
        if self.uid is not None:
            log("Signal sent by user %s" % self.uid)

