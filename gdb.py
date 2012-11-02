#!/usr/bin/env python
from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, Application,
    ProcessExit, NewProcessEvent, ProcessSignal,
    ProcessExecution, ProcessError)
from optparse import OptionParser
from os import getpid
from sys import stdout, stderr, exit
from logging import getLogger, info, warning, error
from ptrace.version import VERSION, WEBSITE
from ptrace.error import PTRACE_ERRORS, writeError
from ptrace.binding import HAS_PTRACE_SINGLESTEP
from ptrace.disasm import HAS_DISASSEMBLER
from ptrace.ctypes_tools import (truncateWord,
    formatWordHex, formatAddress, formatAddressRange, word2bytes)
from ptrace.process_tools import dumpProcessInfo
from ptrace.tools import inverseDict
from ptrace.func_call import FunctionCallOptions
from ptrace.signames import signalName, SIGNAMES
from signal import SIGTRAP, SIGINT
from ptrace.terminal import enableEchoMode, terminalWidth
from errno import ESRCH
from ptrace.cpu_info import CPU_POWERPC
from ptrace.debugger import ChildError
from ptrace.debugger.memory_mapping import readProcessMappings
from ptrace.os_tools import RUNNING_PYTHON3

import re
try:
    # Use readline for better raw_input()
    import readline
except ImportError:
    pass

# Match a register name: $eax, $gp0, $orig_eax
REGISTER_REGEX = re.compile(r"\$[a-z]+[a-z0-9_]+")

#BYTES_REGEX = re.compile(r"""(?:'([^'\\]*)'|"([^"\\]*)")""")

SIGNALS = inverseDict(SIGNAMES)   # name -> signum

COMMANDS = (
    # trace instructions
    ("cont", "continue execution"),
    ("step", "execute one instruction (do not enter in a call)"),
    ("stepi", "execute one instruction (enter the call)"),
    ("until", "execute code until specified address (until <address>)"),
    ("set", "set register value (set <register>=<value>)"),
    ("sys", "continue execution to next syscall"),
    ("signal", "send a signal to the process (signal <signum>)"),
    ("signals", "display signals"),

    # current process info
    ("regs", "display registers"),
    ("where", "display true code content (show breakpoints effects on code). eg. 'where $eip', 'where $eip $eip+20'"),
    ("print", "display a value (print <value>)"),
    ("hexdump", "dump memory as specified address or address range (hexdump <address> or hexdump <start> <stop>)"),
    ("where2", "display original code content (don't show effects of breakpoint on code)"),
    ("stack", "display stack content"),
    ("backtrace", "dump the backtrace"),
    ("proc", "display process information"),
    ("maps", "display memory mappings"),

    # breakpoints
    ("break", "set a breakpoint (break <address>)"),
    ("breakpoints", "display breakpoints"),
    ("delete", "delete a breakpoint (delete <address>)"),

    # processes
    ("attach", 'attach a new process (eg. "attach 2390")'),
    ("proclist", "list of traced processes"),
    ("switch", "switch active process (switch or switch <pid>)"),

    ("follow", r'''follow a term (eg. "follow '\x12\x14\x27\x13'")'''),
    ("showfollow", 'show all "followed" terms'),
    ("resetfollow", 'reset all "followed" terms'),
    ("xray", 'show addresses of (and possible pointers to) "followed" terms'),

    # other
    ("dbginfo", "information about the debugger"),
    ("quit", "quit debugger"),
    ("help", "display this help"),
)

def formatAscii(data):
    def asciiChar(byte):
        if 32 <= byte <= 126:
            return unichr(byte)
        else:
            return '.'
    if RUNNING_PYTHON3:
        return u''.join(asciiChar(byte) for byte in data)
    else:
        return u''.join(asciiChar(ord(byte)) for byte in data)

def formatHexa(data):
    if RUNNING_PYTHON3:
        return u' '.join(u"%02x" % byte for byte in data)
    else:
        return u' '.join(u"%02x" % ord(byte) for byte in data)

# finds possible pointer values in process memory space,
# pointing to address
def getPointers(process, address):
    address = word2bytes(address)
    procmaps = readProcessMappings(process)
    for pm in procmaps:
        for found in pm.search(address):
            yield found

class Gdb(Application):
    def __init__(self):
        Application.__init__(self)

        # Parse self.options
        self.parseOptions()

        # Setup output (log)
        self.setupLog()

        self.last_signal = {}

        # We assume user wants all possible information
        self.syscall_options = FunctionCallOptions(
            write_types=True,
            write_argname=True,
            write_address=True,
        )

        # FIXME: Remove self.breaks!
        self.breaks = dict()

        self.followterms = []

    def setupLog(self):
        self._setupLog(stdout)

    def parseOptions(self):
        parser = OptionParser(usage="%prog [options] -- program [arg1 arg2 ...]")
        self.createCommonOptions(parser)
        self.createLogOptions(parser)
        self.options, self.program = parser.parse_args()

        if self.options.pid is None and not self.program:
            parser.print_help()
            exit(1)

        self.processOptions()
        self.show_pid = self.options.fork

    def _continueProcess(self, process, signum=None):
        if not signum and process in self.last_signal:
            signum = self.last_signal[process]

        if signum:
            error("Send %s to %s" % (signalName(signum), process))
            process.cont(signum)
            try:
                del self.last_signal[process]
            except KeyError:
                pass
        else:
            process.cont()

    def cont(self, signum=None):
        for process in self.debugger:
            process.syscall_state.clear()
            if process == self.process:
                self._continueProcess(process, signum)
            else:
                self._continueProcess(process)

        # Wait for a process signal
        signal = self.debugger.waitSignals()
        process = signal.process

        # Hit breakpoint?
        if signal.signum == SIGTRAP:
            ip = self.process.getInstrPointer()
            if not CPU_POWERPC:
                # Go before "INT 3" instruction
                ip -= 1
            breakpoint = self.process.findBreakpoint(ip)
            if breakpoint:
                error("Stopped at %s" % breakpoint)
                breakpoint.desinstall(set_ip=True)
        else:
            self.processSignal(signal)
        return None

    def readRegister(self, regs):
        name = regs.group(0)[1:]
        value = self.process.getreg(name)
        return str(value)

    def parseInteger(self, text):
        # Remove spaces and convert to lower case
        text = text.strip()
        if " " in text:
            raise ValueError("Space are forbidden: %r" % text)
        text = text.lower()

        # Replace registers by their value
        orig_text = text
        text = REGISTER_REGEX.sub(self.readRegister, text)

        # Replace hexadecimal numbers by decimal numbers
        def readHexadecimal(regs):
            text = regs.group(0)
            if text.startswith("0x"):
                text = text[2:]
            elif not re.search("[a-f]", text):
                return text
            value = int(text, 16)
            return str(value)
        text = re.sub(r"(?:0x)?[0-9a-f]+", readHexadecimal, text)

        # Reject invalid characters
        if not re.match(r"^[()<>+*/&0-9-]+$", text):
            raise ValueError("Invalid expression: %r" % orig_text)

        # Use integer division (a//b) instead of float division (a/b)
        text = text.replace("/", "//")

        # Finally, evaluate the expression
        is_pointer = text.startswith("*")
        if is_pointer:
            text = text[1:]
        try:
            value = eval(text)
            value = truncateWord(value)
        except SyntaxError:
            raise ValueError("Invalid expression: %r" % orig_text)
        if is_pointer:
            value = self.process.readWord(value)
        return value

    def parseIntegers(self, text):
        values = []
        for item in text.split():
            item = item.strip()
            value = self.parseInteger(item)
            values.append(value)
        return values

    def parseBytes(self, text):
        # FIXME: Validate input
#        if not BYTES_REGEX.match(text):
#            raise ValueError('Follow text must be enclosed in quotes!')
        value = eval(text)
        if not isinstance(value, str):
            raise TypeError("Input is not a bytes string!")
        return value

    def addFollowTerm(self, text):
        # Allow terms of the form 'string', "string", '\x04', "\x01\x14"
        term = self.parseBytes(text)
        self.followterms.append(term)

    def showFollowTerms(self):
        print self.followterms

    def _xray(self):
        for term in self.followterms:
            for process in self.debugger:
                for procmap in readProcessMappings(process):
                    for address in procmap.search(term):
                        yield (process, procmap, address, term)

    # displays the offsets of all terms found in the process memory mappings
    # along with possible addresses of pointers pointing to these terms
    def xray(self):
        for process, procmap, address, term in self._xray():
            pointers = " ".join(formatAddress(ptr_addr)
                for ptr_addr in getPointers(process, address))
            print "term[%s] pid[%i] %s %s pointers: %s" % (
                repr(term), process.pid, procmap,
                formatAddress(address),
                pointers)

    def execute(self, command):
        errmsg = None
        if command == "cont":
            errmsg = self.cont()
        elif command == "proc":
            self.procInfo()
        elif command == "proclist":
            self.procList()
        elif command.startswith("attach "):
            errmsg = self.attachProcess(command[7:])
        elif command == "regs":
            self.process.dumpRegs()
        elif command == "stack":
            self.process.dumpStack()
        elif command == "backtrace":
            errmsg = self.backtrace()
        elif command == "where" or command.startswith("where "):
            errmsg = self.where(command[6:])
        elif command == "where2" or command.startswith("where2 "):
            errmsg = self.where(command[7:], manage_bp=True)
        elif command == "maps":
            self.process.dumpMaps()
        elif command == "dbginfo":
            self.debuggerInfo()
        elif command == "step":
            errmsg = self.step(False)
        elif command == "stepi":
            errmsg = self.step(True)
        elif command == "sys":
            errmsg = self.syscallTrace()
        elif command == "help":
            self.help()
        elif command.startswith("set "):
            errmsg = self.set(command)
        elif command.startswith("until "):
            errmsg = self.until(command[6:])
        elif command.startswith("switch") or command == "switch":
            errmsg = self.switch(command[6:])
        elif command.startswith("break "):
            errmsg = self.breakpoint(command[6:])
        elif command.startswith("breakpoints"):
            self.displayBreakpoints()
        elif command.startswith("signals"):
            self.displaySignals()
        elif command.startswith("delete "):
            errmsg = self.delete(command[7:])
        elif command.startswith("hexdump "):
            errmsg = self.hexdump(command[8:])
        elif command.startswith("signal "):
            errmsg = self.signal(command[7:])
        elif command.startswith("print "):
            errmsg = self.print_(command[6:])
        elif command.startswith("follow "):
            errmsg = self.addFollowTerm(command[7:])
        elif command == "showfollow":
            self.showFollowTerms()
        elif command == "resetfollow":
            self.followterms = []
        elif command == "xray":
            self.xray()
        else:
            errmsg = "Unknown command: %r" % command
        if errmsg:
            print >>stderr, errmsg
            return False
        return True

    def parseSignum(self, command):
        try:
            return SIGNALS[command]
        except KeyError:
            pass
        try:
            return SIGNALS["SIG"+command]
        except KeyError:
            pass
        try:
            return self.parseInteger(command)
        except ValueError, err:
            raise ValueError("Invalid signal number: %r" % command)

    def signal(self, command):
        try:
            signum = self.parseSignum(command)
        except ValueError, err:
            return str(err)
        last_process = self.process
        try:
            errmsg = self.cont(signum)
            return errmsg
        finally:
            try:
                del self.last_signal[last_process]
            except KeyError:
                pass

    def print_(self, command):
        try:
            value = self.parseInteger(command)
        except ValueError, err:
            return str(err)
        error("Decimal: %s" % value)
        error("Hexadecimal: %s" % formatWordHex(value))
        for map in self.process.readMappings():
            if value not in map:
                continue
            error("Address is part of mapping: %s" % map)
        return None

    def hexdump(self, command):
        max_line = 20
        width = (terminalWidth() - len(formatAddress(1)) - 3) // 4
        width = max(width, 1)

        limited = None
        parts = command.split(" ", 1)
        if 1 < len(parts):
            try:
                start_address = self.parseInteger(parts[0])
                end_address = self.parseInteger(parts[1])
                if end_address <= start_address:
                    raise ValueError('End address (%s) is smaller than start address(%s)!'
                        % (formatAddress(end_address), formatAddress(start_address)))
            except ValueError, err:
                return str(err)
            size = end_address - start_address
            max_size = width*max_line
            if max_size < size:
                limited = max_size
                end_address = start_address + max_size
        else:
            try:
                start_address = self.parseInteger(command)
            except ValueError, err:
                return str(err)
            end_address = start_address + 5*width

        read_error = None
        address = start_address
        while address < end_address:
            size = min(end_address - address, width)
            try:
                # Read bytes
                memory = self.process.readBytes(address, size)

                # Format bytes
                hexa = formatHexa(memory)
                hexa = hexa.ljust(width*3-1, u' ')

                ascii = formatAscii(memory)
                ascii = ascii.ljust(width, u' ')

                # Display previous read error, if any
                if read_error:
                    warning("Warning: Unable to read memory %s" % (
                        formatAddressRange(*read_error)))
                    read_error = None

                # Display line
                error(u"%s| %s| %s" % (formatAddress(address), hexa, ascii))
            except PtraceError:
                if not read_error:
                    read_error = [address, address + size]
                else:
                    read_error[1] = address + size
            address += size

        # Display last read error, if any
        if read_error:
            warning("Warning: Unable to read memory %s" % (
                formatAddressRange(*read_error)))
        if limited:
            warning("(limit to %s bytes)" % max_size)
        return None

    def backtrace(self):
        trace = self.process.getBacktrace()
        for func in trace:
            error(func)
        if trace.truncated:
            error("--limited to depth %s--" % len(trace))
        return None

    def where(self, command, manage_bp=False):
        start = None
        stop = None
        try:
            values = self.parseIntegers(command)
        except ValueError, err:
            return str(err)
        if 1 <= len(values):
            start = values[0]
        if 2 <= len(values):
            stop = values[1]
        self.process.dumpCode(start, stop, manage_bp=manage_bp)
        return None

    def procInfo(self):
        dumpProcessInfo(error, self.process.pid, max_length=160)

    def procList(self):
        for process in self.debugger:
            text = str(process)
            if self.process == process:
                text += " (active)"
            error(text)

    def set(self, command):
        try:
            key, value = command[4:].split("=", 1)
            key = key.strip().lower()
            if not key.startswith("$"):
                return 'Register name (%s) have to start with "$"' % key
            key = key[1:]
        except ValueError, err:
             return "Invalid command: %r" % command
        try:
            value = self.parseInteger(value)
        except ValueError, err:
            return str(err)
        try:
            self.process.setreg(key, value)
        except ProcessError, err:
            return "Unable to set $%s=%s: %s" % (key, value, err)
        error("Set $%s to %s" % (key, value))
        return None

    def displayInstr(self, prefix):
        try:
            if HAS_DISASSEMBLER:
                instr = self.process.disassembleOne()
                error("%s %s: %s" % (
                    prefix, formatAddress(instr.address), instr.text))
            else:
                self.process.dumpCode()
        except PtraceError, err:
            error("Unable to read current instruction: %s" % err)

    def attachProcess(self, text):
        try:
            pid = self.parseInteger(text)
        except ValueError, err:
             return str(err)
        process = self.debugger.addProcess(pid, False)
        self.switchProcess(process)

    def step(self, enter_call, address=None):
        if address is None:
            self.displayInstr("Execute")
        if (not HAS_PTRACE_SINGLESTEP) or (not enter_call):
            if address is None:
                address = self.process.getInstrPointer()
                size = self.readInstrSize(address, default_size=None)
                if not size:
                    return "Unable to read instruction size at %s" \
                        % formatAddress(address)
                address += size
            size = self.readInstrSize(address)

            # Set a breakpoint
            breakpoint = self.process.createBreakpoint(address, size)

            # Continue the process
            self.process.cont()
        else:
            # Use ptrace single step command
            self.process.singleStep()
            breakpoint = None

        # Execute processus until next TRAP
        try:
            self.process.waitSignals(SIGTRAP)
            if breakpoint:
                breakpoint.desinstall(set_ip=True)
        except:
            if breakpoint:
                breakpoint.desinstall()
            raise
        return None

    def newProcess(self, event):
        error("New process: %s" % event.process)

    # FIXME: This function doesn't work multiple multiple processes
    # especially when a parent waits for a child
    def syscallTrace(self):
        # Trace until syscall enter
        self.process.syscall()
        self.process.waitSyscall()

        # Process the syscall event
        state = self.process.syscall_state
        syscall = state.event(self.syscall_options)

        # Display syscall
        if syscall:
            if syscall.result is not None:
                text = "%s = %s" % (syscall.format(), syscall.result_text)
                if self.show_pid:
                    text = "Process %s exits %s" % (syscall.process.pid, text)
                error(text)
            else:
                text = syscall.format()
                if self.show_pid:
                    text = "Process %s enters %s" % (syscall.process.pid, text)
                error(text)
        return None

    def until(self, command):
        try:
            address = self.parseInteger(command)
        except ValueError, err:
             return str(err)
        errmsg = self.step(False, address)
        if errmsg:
            return errmsg
        self.displayInstr("Current")
        return None

    def switch(self, command):
        if not command:
            process_list = self.debugger.list
            if len(process_list) == 1:
                return "There is only one process!"
            index = process_list.index(self.process)
            index = (index + 1) % len(process_list)
            process = process_list[index]
            self.switchProcess(process)
            return
        try:
            pid = self.parseInteger(command)
        except ValueError, err:
             return str(err)
        try:
            process = self.debugger[pid]
            self.switchProcess(process)
        except KeyError:
            return "There is not process %s" % pid
        return None

    def switchProcess(self, process):
        if self.process == process:
            return
        error("Switch to %s" % process)
        self.process = process

    def nextProcess(self):
        try:
            process = iter(self.debugger).next()
            self.switchProcess(process)
        except StopIteration:
            pass

    def displayBreakpoints(self):
        found = False
        for process in self.debugger:
            for bp in process.breakpoints.itervalues():
                found = True
                error("%s:%s" % (process, bp))
        if not found:
            error("(no breakpoint)")

    def displaySignals(self):
        signals = SIGNAMES.items()
        signals.sort(key=lambda (key, value): key)
        for signum, name in signals:
            error("% 2s: %s" % (signum, name))

    def readInstrSize(self, address, default_size=None):
        if not HAS_DISASSEMBLER:
            return default_size
        try:
            # Get address and size of instruction at specified address
            instr = self.process.disassembleOne(address)
            return instr.size
        except PtraceError, err:
            warning("Warning: Unable to read instruction size at %s: %s" % (
                formatAddress(address), err))
            return default_size

    def breakpoint(self, command):
        try:
            address = self.parseInteger(command)
        except ValueError, err:
            return str(err)

        # Create breakpoint
        size = self.readInstrSize(address)
        try:
            bp = self.process.createBreakpoint(address, size)
        except PtraceError, err:
            return "Unable to set breakpoint at %s: %s" % (
                formatAddress(address), err)
        error("New breakpoint: %s" % bp)
        return None

    def delete(self, command):
        try:
            address = self.parseInteger(command)
        except ValueError, err:
            return str(err)

        breakpoint = self.process.findBreakpoint(address)
        if not breakpoint:
            return "No breakpoint at %s " % formatAddress(address)
        breakpoint.desinstall()
        error("%s deleted" % breakpoint)
        return None

    def help(self):
        for command, description in COMMANDS:
            error("%s: %s" % (command, description))
        error('')
        error("Value can be an hexadecimal/decimal number or a register name ($reg)")
        error("You can use operators a+b, a-b, a*b, a/b, a<<b, a>>b, a**b, and parenthesis in expressions")
        error('Use ";" to write multiple commands on the same line (eg. "step; print $eax")')

    def processSignal(self, event):
        event.display()
        self.switchProcess(event.process)
        self.last_signal[self.process] = event.signum
        error("%s interrupted by %s" % (self.process, event.name))

    def processExecution(self, event):
        error(event)
        self.switchProcess(event.process)
        self.interrupt()

    def debuggerInfo(self):
        error("Debugger process ID: %s" % getpid())
        error("python-ptrace version %s" % VERSION)
        error("Website: %s" % WEBSITE)

    def interrupt(self):
        waitlist = []
        for process in self.debugger:
            if process.is_stopped:
                continue
            try:
                if process.isTraced():
                    continue
            except NotImplementedError:
                pass
            warning("Interrupt %s (send SIGINT)" % process)
            process.kill(SIGINT)
            waitlist.append(process)
        for process in waitlist:
            info("Wait %s interruption" % process)
            try:
                process.waitSignals(SIGINT)
            except ProcessSignal, event:
                event.display()
            except KeyboardInterrupt:
                pass

    def deleteProcess(self, pid):
        try:
            process = self.debugger[pid]
        except KeyError:
            return
        event = process.processTerminated()
        error(str(event))
        if process == self.process:
            self.nextProcess()

    def restoreTerminal(self):
        if enableEchoMode():
            error("Terminal: restore echo mode")

    def mainLoop(self):
        # Read command
        try:
            self.restoreTerminal()
            command = raw_input(self.invite).strip()
        except EOFError:
            print
            return True
        except KeyboardInterrupt:
            error("User interrupt!")
            self.interrupt()
            return False

        # If command is empty, reuse previous command
        if not command:
            if self.previous_command:
                command = self.previous_command
                info("Replay previous command: %s" % command)
            else:
                return False
        self.previous_command = None

        # User wants to quit?
        if command == "quit":
            return True

        # Execute the user command
        try:
            command_str = command
            ok = True
            for command in command_str.split(";"):
                command = command.strip()
                try:
                    ok &= self.execute(command)
                except Exception, err:
                    print "Command error: %s" % err
                    ok = False
                if not ok:
                    break
            if ok:
                self.previous_command = command_str
        except KeyboardInterrupt:
            self.interrupt()
        except NewProcessEvent, event:
            self.newProcess(event)
        except ProcessSignal, event:
            self.processSignal(event)
        except ProcessExit, event:
            error(event)
            self.nextProcess()
        except ProcessExecution, event:
            self.processExecution(event)
        except PtraceError, err:
            error("ERROR: %s" % err)
            if err.errno == ESRCH:
                self.deleteProcess(err.pid)
        return False

    def runDebugger(self):
        self.setupDebugger()

        # Create new process
        try:
            self.process = self.createProcess()
        except ChildError, err:
            writeError(getLogger(), err, "Unable to create child process")
            return
        if not self.process:
            return

        # Trace syscalls
        self.invite = '(gdb) '
        self.previous_command = None
        while True:
            if not self.debugger:
                # There is no more process: quit
                return
            done = self.mainLoop()
            if done:
                return

    def main(self):
        self.debugger = PtraceDebugger()
        try:
            self.runDebugger()
        except KeyboardInterrupt:
            error("Interrupt debugger: quit!")
        except PTRACE_ERRORS, err:
            writeError(getLogger(), err, "Debugger error")
        self.process = None
        self.debugger.quit()
        error("Quit gdb.")
        self.restoreTerminal()

if __name__ == "__main__":
    Gdb().main()

