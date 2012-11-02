from ptrace.binding import (
    HAS_PTRACE_SINGLESTEP, HAS_PTRACE_EVENTS,
    HAS_PTRACE_SIGINFO, HAS_PTRACE_IO, HAS_PTRACE_GETREGS,
    ptrace_attach, ptrace_detach,
    ptrace_cont, ptrace_syscall,
    ptrace_setregs,
    ptrace_peektext, ptrace_poketext,
    REGISTER_NAMES)
if HAS_PTRACE_SINGLESTEP:
    from ptrace.binding import ptrace_singlestep
if HAS_PTRACE_SIGINFO:
    from ptrace.binding import ptrace_getsiginfo
if HAS_PTRACE_IO:
    from ctypes import create_string_buffer, addressof
    from ptrace.binding import (
        ptrace_io, ptrace_io_desc,
        PIOD_READ_D, PIOD_WRITE_D)
if HAS_PTRACE_EVENTS:
    from ptrace.binding import (
        ptrace_setoptions, ptrace_geteventmsg, WPTRACEEVENT,
        PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE,
        PTRACE_EVENT_EXEC)
    NEW_PROCESS_EVENT = (PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE)
if HAS_PTRACE_GETREGS:
    from ptrace.binding import ptrace_getregs
else:
    from ptrace.binding import ptrace_peekuser, ptrace_registers_t
from ptrace.os_tools import HAS_PROC, RUNNING_BSD
from ptrace.tools import dumpRegs
from ptrace.cpu_info import CPU_WORD_SIZE, CPU_64BITS
from ptrace.ctypes_tools import bytes2word, word2bytes, bytes2type, bytes2array
from signal import SIGTRAP, SIGSTOP, SIGKILL
from ptrace.ctypes_tools import formatAddress, formatWordHex
from ctypes import sizeof, c_char_p
from logging import info, warning, error
from ptrace.error import PtraceError
from errno import ESRCH, EACCES
from ptrace.debugger import (Breakpoint,
    ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from os import (kill,
    WIFSTOPPED, WSTOPSIG,
    WIFSIGNALED, WTERMSIG,
    WIFEXITED, WEXITSTATUS)
from ptrace.disasm import HAS_DISASSEMBLER
if HAS_DISASSEMBLER:
    from ptrace.disasm import disassemble, disassembleOne, MAX_INSTR_SIZE
from ptrace.debugger.backtrace import getBacktrace
from ptrace.debugger.process_error import ProcessError
from ptrace.debugger.memory_mapping import readProcessMappings
from ptrace.binding.cpu import CPU_INSTR_POINTER, CPU_STACK_POINTER, CPU_FRAME_POINTER, CPU_SUB_REGISTERS
from ptrace.debugger.syscall_state import SyscallState
from ptrace.six import b
if HAS_PROC:
    from ptrace.linux_proc import readProcessStat

MIN_CODE_SIZE = 32
MAX_CODE_SIZE = 1024
DEFAULT_NB_INSTR = 10
DEFAULT_CODE_SIZE = 24

class PtraceProcess(object):
    """
    Process traced by a PtraceDebugger.

    Methods
    =======

     * control execution:

       - singleStep(): execute one instruction
       - cont(): continue the execution
       - syscall(): break at next syscall
       - setInstrPointer(): change the instruction pointer
       - kill(): send a signal to the process
       - terminate(): kill the process

     * wait an event:

      - waitEvent(): wait next process event
      - waitSignals(): wait a signal

     * get status

       - getreg(): get a register
       - getInstrPointer(): get the instruction pointer
       - getStackPointer(): get the stack pointer
       - getFramePointer(): get the stack pointer
       - getregs(): get all registers, eg. regs=getregs(); print regs.eax
       - disassemble(): assembler code of the next instructions
       - disassembleOne(): assembler code of the next instruction
       - findStack(): get stack memory mapping
       - getsiginfo(): get signal information
       - getBacktrace(): get the current backtrace

     * set status

       - setreg(): set a register
       - setregs(): set all registers

     * memory access:

       - readWord(): read a memory word
       - readBytes(): read some bytes
       - readStruct(): read a structure
       - readArray(): read an array
       - readCString(): read a C string
       - readMappings(): get all memory mappings
       - writeWord(): write a memory word
       - writeBytes(): write some bytes

     * display status:

       - dumpCore(): display the next instructions
       - dumpStack(): display some memory words around the stack pointer
       - dumpMaps(): display memory mappings
       - dumpRegs(): display all registers

     * breakpoint:

       - createBreakpoint(): set a breakpoint
       - findBreakpoint(): find a breakpoint
       - removeBreakpoint(): remove a breakpoint

     * other:

       - setoptions(): set ptrace options

    See each method to get better documentation. You are responsible
    to manage the process state: some methods may fail or crash your
    processus if they are called when the process is in the wrong
    state.

    Attributes
    ==========

     * main attributes:
       - pid: identifier of the process
       - debugger: PtraceDebugger instance
       - breakpoints: dictionary of active breakpoints
       - parent: parent PtraceProcess (None if process has no parent)

     * state:
       - running: if True, the process is alive, otherwise the process
         doesn't exist anymore
       - exited: if True, the process has exited (attributed only used
         on BSD operation systems)
       - is_attached: if True, the process is attached by ptrace
       - was_attached: if True, the process will be detached at exit
       - is_stopped: if True, the process is stopped, otherwise it's
         running
       - syscall_state: control syscall tracing

    Sometimes, is_stopped value is wrong. You might use isTraced() to
    make sure that the process is stopped.
    """
    def __init__(self, debugger, pid, is_attached, parent=None):
        self.debugger = debugger
        self.breakpoints = {}
        self.pid = pid
        self.running = True
        self.exited = False
        self.parent = parent
        self.was_attached = is_attached
        self.is_attached = False
        self.is_stopped = True
        if not is_attached:
            self.attach()
        else:
            self.is_attached = True
        if HAS_PROC:
            self.read_mem_file = None
        self.syscall_state = SyscallState(self)

    def isTraced(self):
        if not HAS_PROC:
            self.notImplementedError()
        stat = readProcessStat(self.pid)
        return (stat.state == 'T')

    def attach(self):
        if self.is_attached:
            return
        info("Attach process %s" % self.pid)
        ptrace_attach(self.pid)
        self.is_attached = True

    def dumpCode(self, start=None, stop=None, manage_bp=False, log=None):
        if not log:
            log = error
        try:
            ip = self.getInstrPointer()
        except PtraceError, err:
            if start is None:
                log("Unable to read instruction pointer: %s" % err)
                return
            ip = None
        if start is None:
            start = ip

        try:
            self._dumpCode(start, stop, ip, manage_bp, log)
        except PtraceError, err:
            log("Unable to dump code at %s: %s" % (
                formatAddress(start), err))

    def _dumpCode(self, start, stop, ip, manage_bp, log):
        if stop is not None:
            stop = max(start, stop)
            stop = min(stop, start + MAX_CODE_SIZE - 1)

        if not HAS_DISASSEMBLER:
            if stop is not None:
                size = stop - start + 1
            else:
                size = MIN_CODE_SIZE
            code = self.readBytes(start, size)
            text = " ".join( "%02x" % ord(byte) for byte in code )
            log("CODE: %s" % text)
            return

        if manage_bp:
            address = start
            for line in xrange(10):
                bp = False
                if address in self.breakpoints:
                    bytes = self.breakpoints[address].old_bytes
                    instr = disassembleOne(bytes, address)
                    bp = True
                else:
                    instr = self.disassembleOne(address)
                text = "%s| %s (%s)" % (formatAddress(instr.address), instr.text, instr.hexa)
                if instr.address == ip:
                    text += " <=="
                if bp:
                    text += "     * BREAKPOINT *"
                log(text)
                address = address+instr.size
                if stop is not None and stop <= address:
                    break
        else:
            for instr in self.disassemble(start, stop):
                text = "%s| %s (%s)" % (formatAddress(instr.address), instr.text, instr.hexa)
                if instr.address == ip:
                    text += " <=="
                log(text)

    def disassemble(self, start=None, stop=None, nb_instr=None):
        if not HAS_DISASSEMBLER:
            self.notImplementedError()
        if start is None:
            start = self.getInstrPointer()
        if stop is not None:
            stop = max(start, stop)
            size = stop - start + 1
        else:
            if nb_instr is None:
                nb_instr = DEFAULT_NB_INSTR
            size = nb_instr * MAX_INSTR_SIZE

        code = self.readBytes(start, size)
        for index, instr in enumerate(disassemble(code, start)):
            yield instr
            if nb_instr and nb_instr <= (index+1):
                break

    def disassembleOne(self, address=None):
        if not HAS_DISASSEMBLER:
            self.notImplementedError()
        if address is None:
            address = self.getInstrPointer()
        code = self.readBytes(address, MAX_INSTR_SIZE )
        return disassembleOne(code, address)

    def findStack(self):
        for map in self.readMappings():
            if map.pathname == "[stack]":
                return map
        return None

    def detach(self):
        if not self.is_attached:
            return
        self.is_attached = False
        if self.running:
            if self.was_attached:
                info("Detach %s" % self)
                ptrace_detach(self.pid)
            elif self.is_stopped:
                info("Continue process %s execution" % self.pid)
                self.cont()
        self.debugger.deleteProcess(process=self)

    def _notRunning(self):
        self.running = False
        if HAS_PROC and self.read_mem_file:
            try:
                self.read_mem_file.close()
            except IOError:
                pass
        self.detach()

    def kill(self, signum):
        kill(self.pid, signum)

    def terminate(self, wait_exit=True):
        if not self.running or not self.was_attached:
            return True
        warning("Terminate %s" % self)
        done = False
        try:
            if self.is_stopped:
                self.cont(SIGKILL)
            else:
                self.kill(SIGKILL)
        except PtraceError, event:
            if event.errno == ESRCH:
                done = True
            else:
                raise event
        if not done:
            if not wait_exit:
                return False
            self.waitExit()
        self._notRunning()
        return True

    def waitExit(self):
        while True:
            # Wait for any process signal
            event = self.waitEvent()
            event_cls = event.__class__

            # Process exited: we are done
            if event_cls == ProcessExit:
                return

            # Event different than a signal? Raise an exception
            if event_cls != ProcessSignal:
                raise event

            # Send the signal to the process
            signum = event.signum
            if signum not in (SIGTRAP, SIGSTOP):
                self.cont(signum)
            else:
                self.cont()

    def processStatus(self, status):
        # Process exited?
        if WIFEXITED(status):
            code = WEXITSTATUS(status)
            event = self.processExited(code)

        # Process killed by a signal?
        elif WIFSIGNALED(status):
            signum = WTERMSIG(status)
            event = self.processKilled(signum)

        # Invalid process status?
        elif not WIFSTOPPED(status):
            raise ProcessError(self, "Unknown process status: %r" % status)

        # Ptrace event?
        elif HAS_PTRACE_EVENTS and WPTRACEEVENT(status):
            event = WPTRACEEVENT(status)
            event = self.ptraceEvent(event)

        else:
            signum = WSTOPSIG(status)
            event = self.processSignal(signum)
        return event

    def processTerminated(self):
        self._notRunning()
        return ProcessExit(self)

    def processExited(self, code):
        if RUNNING_BSD and not self.exited:
            # on FreeBSD, we have to waitpid() twice
            # to avoid zombi process!?
            self.exited = True
            self.waitExit()
        self._notRunning()
        return ProcessExit(self, exitcode=code)

    def processKilled(self, signum):
        self._notRunning()
        return ProcessExit(self, signum=signum)

    def processSignal(self, signum):
        self.is_stopped = True
        return ProcessSignal(signum, self)

    def ptraceEvent(self, event):
        if not HAS_PTRACE_EVENTS:
            self.notImplementedError()
        if event in NEW_PROCESS_EVENT:
            new_pid = ptrace_geteventmsg(self.pid)
            new_process = self.debugger.addProcess(new_pid, is_attached=True, parent=self)
            return NewProcessEvent(new_process)
        elif event == PTRACE_EVENT_EXEC:
            return ProcessExecution(self)
        else:
            raise ProcessError(self, "Unknown ptrace event: %r" % event)

    def getregs(self):
        if HAS_PTRACE_GETREGS:
            return ptrace_getregs(self.pid)
        else:
            # FIXME: Optimize getreg() when used with this function
            words = []
            nb_words = sizeof(ptrace_registers_t) // CPU_WORD_SIZE
            for offset in xrange(nb_words):
                word = ptrace_peekuser(self.pid, offset*CPU_WORD_SIZE)
                bytes = word2bytes(word)
                words.append(bytes)
            bytes = ''.join(words)
            return bytes2type(bytes, ptrace_registers_t)

    def getreg(self, name):
        try:
            name, shift, mask = CPU_SUB_REGISTERS[name]
        except KeyError:
            shift = 0
            mask = None
        if name not in REGISTER_NAMES:
            raise ProcessError(self, "Unknown register: %r" % name)
        regs = self.getregs()
        value = getattr(regs, name)
        value >>= shift
        if mask:
            value &= mask
        return value

    def setregs(self, regs):
        ptrace_setregs(self.pid, regs)

    def setreg(self, name, value):
        regs = self.getregs()
        if name in CPU_SUB_REGISTERS:
            full_name, shift, mask = CPU_SUB_REGISTERS[name]
            full_value = getattr(regs, full_name)
            full_value &= ~mask
            full_value |= ((value & mask) << shift)
            value = full_value
            name = full_name
        if name not in REGISTER_NAMES:
            raise ProcessError(self, "Unknown register: %r" % name)
        setattr(regs, name, value)
        self.setregs(regs)

    def singleStep(self):
        if not HAS_PTRACE_SINGLESTEP:
            self.notImplementedError()
        ptrace_singlestep(self.pid)

    def filterSignal(self, signum):
        if signum == SIGTRAP:
            # Never transfer SIGTRAP signal
            return 0
        else:
            return signum

    def syscall(self, signum=0):
        signum = self.filterSignal(signum)
        ptrace_syscall(self.pid, signum)
        self.is_stopped = False

    def setInstrPointer(self, ip):
        if CPU_INSTR_POINTER:
            self.setreg(CPU_INSTR_POINTER, ip)
        else:
            raise ProcessError(self, "Instruction pointer is not defined")

    def getInstrPointer(self):
        if CPU_INSTR_POINTER:
            return self.getreg(CPU_INSTR_POINTER)
        else:
            raise ProcessError(self, "Instruction pointer is not defined")

    def getStackPointer(self):
        if CPU_STACK_POINTER:
            return self.getreg(CPU_STACK_POINTER)
        else:
            raise ProcessError(self, "Instruction pointer is not defined")

    def getFramePointer(self):
        if CPU_FRAME_POINTER:
            return self.getreg(CPU_FRAME_POINTER)
        else:
            raise ProcessError(self, "Instruction pointer is not defined")

    def _readBytes(self, address, size):
        offset = address % CPU_WORD_SIZE
        if offset:
            # Read word
            address -= offset
            word = self.readWord(address)
            bytes = word2bytes(word)

            # Read some bytes from the word
            subsize = min(CPU_WORD_SIZE - offset, size)
            data = bytes[offset:offset+subsize]   # <-- FIXME: Big endian!

            # Move cursor
            size -= subsize
            address += CPU_WORD_SIZE
        else:
            data = b('')

        while size:
            # Read word
            word = self.readWord(address)
            bytes = word2bytes(word)

            # Read bytes from the word
            if size < CPU_WORD_SIZE:
                data += bytes[:size]   # <-- FIXME: Big endian!
                break
            data += bytes

            # Move cursor
            size -= CPU_WORD_SIZE
            address += CPU_WORD_SIZE
        return data

    def readWord(self, address):
        """Address have to be aligned!"""
        word = ptrace_peektext(self.pid, address)
        return word

    if HAS_PTRACE_IO:
        def readBytes(self, address, size):
            buffer = create_string_buffer(size)
            io_desc = ptrace_io_desc(
                piod_op=PIOD_READ_D,
                piod_offs=address,
                piod_addr=addressof(buffer),
                piod_len=size)
            ptrace_io(self.pid, io_desc)
            return buffer.raw
    elif HAS_PROC:
        def readBytes(self, address, size):
            if not self.read_mem_file:
                filename = '/proc/%u/mem' % self.pid
                try:
                    self.read_mem_file = open(filename, 'rb', 0)
                except IOError, err:
                    message = "Unable to open %s: fallback to ptrace implementation" % filename
                    if err.errno != EACCES:
                        error(message)
                    else:
                        info(message)
                    self.readBytes = self._readBytes
                    return self.readBytes(address, size)

            try:
                mem = self.read_mem_file
                mem.seek(address)
                return mem.read(size)
            except (IOError, ValueError), err:
                raise ProcessError(self, "readBytes(%s, %s) error: %s" % (
                    formatAddress(address), size, err))
    else:
        readBytes = _readBytes

    def getsiginfo(self):
        if not HAS_PTRACE_SIGINFO:
            self.notImplementedError()
        return ptrace_getsiginfo(self.pid)

    def writeBytes(self, address, bytes):
        if HAS_PTRACE_IO:
            size = len(bytes)
            bytes = create_string_buffer(bytes)
            io_desc = ptrace_io_desc(
                piod_op=PIOD_WRITE_D,
                piod_offs=address,
                piod_addr=addressof(bytes),
                piod_len=size)
            ptrace_io(self.pid, io_desc)
        else:
            offset = address % CPU_WORD_SIZE
            if offset:
                # Write partial word (end)
                address -= offset
                size = CPU_WORD_SIZE - offset
                word = self.readBytes(address, CPU_WORD_SIZE)
                if len(bytes) < size:
                    size = len(bytes)
                    word = word[:offset] + bytes[:size] + word[offset + size:]  # <-- FIXME: Big endian!
                else:
                    word = word[:offset] + bytes[:size]   # <-- FIXME: Big endian!
                self.writeWord(address, bytes2word(word))
                bytes = bytes[size:]
                address += CPU_WORD_SIZE

            # Write full words
            while CPU_WORD_SIZE <= len(bytes):
                # Read one word
                word = bytes[:CPU_WORD_SIZE]
                word = bytes2word(word)
                self.writeWord(address, word)

                # Move to next word
                bytes = bytes[CPU_WORD_SIZE:]
                address += CPU_WORD_SIZE
            if not bytes:
                return

            # Write partial word (begin)
            size = len(bytes)
            word = self.readBytes(address, CPU_WORD_SIZE)
            # FIXME: Write big endian version of the next line
            word = bytes + word[size:]
            self.writeWord(address, bytes2word(word))

    def readStruct(self, address, struct):
        bytes = self.readBytes(address, sizeof(struct))
        if not CPU_64BITS:
            bytes = c_char_p(bytes)
        return bytes2type(bytes, struct)

    def readArray(self, address, basetype, count):
        bytes = self.readBytes(address, sizeof(basetype)*count)
        if not CPU_64BITS:
            bytes = c_char_p(bytes)
        return bytes2array(bytes, basetype, count)

    def readCString(self, address, max_size, chunk_length=256):
        string = []
        size = 0
        truncated = False
        while True:
            done = False
            data = self.readBytes(address, chunk_length)
            pos = data.find(b('\0'))
            if pos != -1:
                done = True
                data = data[:pos]
            if max_size <= size+chunk_length:
                data = data[:(max_size-size)]
                string.append(data)
                truncated = True
                break
            string.append(data)
            if done:
                break
            size += chunk_length
            address += chunk_length
        return ''.join(string), truncated

    def dumpStack(self, log=None):
        if not log:
            log = error
        stack = self.findStack()
        if stack:
            log("STACK: %s" % stack)
        self._dumpStack(log)

    def _dumpStack(self, log):
        sp = self.getStackPointer()
        displayed = 0
        for index in xrange(-5, 5+1):
            delta = index * CPU_WORD_SIZE
            try:
                value = self.readWord(sp + delta)
                log("STACK%+ 3i: %s" % (delta, formatWordHex(value)))
                displayed += 1
            except PtraceError:
                pass
        if not displayed:
            log("ERROR: unable to read the stack (SP=%s)" % formatAddress(sp))

    def readMappings(self):
        return readProcessMappings(self)

    def dumpMaps(self, log=None):
        if not log:
            log = error
        for map in self.readMappings():
            log("MAPS: %s" % map)

    def writeWord(self, address, word):
        """
        Address have to be aligned!
        """
        ptrace_poketext(self.pid, address, word)

    def dumpRegs(self, log=None):
        if not log:
            log = error
        try:
            regs = self.getregs()
            dumpRegs(log, regs)
        except PtraceError, err:
            log("Unable to read registers: %s" % err)

    def cont(self, signum=0):
        signum = self.filterSignal(signum)
        ptrace_cont(self.pid, signum)
        self.is_stopped = False

    def setoptions(self, options):
        if not HAS_PTRACE_EVENTS:
            self.notImplementedError()
        info("Set %s options to %s" % (self, options))
        ptrace_setoptions(self.pid, options)

    def waitEvent(self):
        return self.debugger.waitProcessEvent(pid=self.pid)

    def waitSignals(self, *signals):
        return self.debugger.waitSignals(*signals, **{'pid': self.pid})

    def waitSyscall(self):
        self.debugger.waitSyscall(self)

    def findBreakpoint(self, address):
        for bp in self.breakpoints.itervalues():
            if bp.address <= address < bp.address + bp.size:
                return bp
        return None

    def createBreakpoint(self, address, size=1):
        bp = self.findBreakpoint(address)
        if bp:
            raise ProcessError(self, "A breakpoint is already set: %s" % bp)
        bp = Breakpoint(self, address, size)
        self.breakpoints[address] = bp
        return bp

    def getBacktrace(self, max_args=6, max_depth=20):
        return getBacktrace(self, max_args=max_args, max_depth=max_depth)

    def removeBreakpoint(self, breakpoint):
        del self.breakpoints[breakpoint.address]

    def __del__(self):
        try:
            self.detach()
        except PtraceError:
            pass

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<PtraceProcess #%s>" % self.pid

    def __hash__(self):
        return hash(self.pid)

    def notImplementedError(self):
        raise NotImplementedError()

