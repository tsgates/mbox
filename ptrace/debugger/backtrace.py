from ptrace.ctypes_tools import formatAddress, formatWordHex
from ptrace.cpu_info import CPU_WORD_SIZE, CPU_MAX_UINT
from ptrace import PtraceError

class BacktraceFrame(object):
    """
    Backtrace frame.

    Attributes:
     - ip: instruction pointer
     - name: name of the function
     - arguments: value of the arguments
    """
    def __init__(self, ip):
        self.ip = ip
        self.name = u"???"
        self.arguments = []

    def __str__(self):
        arguments = (formatWordHex(arg) for arg in self.arguments)
        return u"IP=%s: %s (%s)" % (formatAddress(self.ip), self.name, ", ".join(arguments))

class Backtrace(object):
    """
    Backtrace: all process frames since the start function.
    """
    def __init__(self):
        self.frames = []
        self.truncated = False

    def append(self, frame):
        self.frames.append(frame)

    def __iter__(self):
        return iter(self.frames)

    def __len__(self):
        return len(self.frames)

def getBacktrace(process, max_args=6, max_depth=20):
    """
    Get the current backtrace of the specified process:
     - max_args: maximum number of arguments in a frame
     - max_depth: maximum number of frames

    Return a Backtrace object.
    """
    backtrace = Backtrace()

    # Get current instruction and frame pointer
    ip = process.getInstrPointer()
    fp = process.getFramePointer()
    depth = 0
    while True:
        # Hit maximum trace depth?
        if max_depth <= depth:
            backtrace.truncated = True
            break

        # Read next frame pointer
        try:
            nextfp = process.readWord(fp)
        except PtraceError:
            nextfp = None

        # Guess number of function argument
        if fp and nextfp:
            nargs = ((nextfp - fp) // CPU_WORD_SIZE) - 2
            nargs = min(nargs, max_args)
        else:
            nargs = 0

        # Create frame
        frame = getBacktraceFrame(process, ip, fp, nargs)
        backtrace.append(frame)

        # End of the stack?
        if not nextfp:
            break

        # Move to next instruction/frame pointer
        ip = process.readWord(fp+CPU_WORD_SIZE)
        if ip == CPU_MAX_UINT:
            # Linux hack to detect end of the stack
            break
        fp = nextfp
        depth += 1
    return backtrace

def getBacktraceFrame(process, ip, fp, nargs):
    """
    Get a backtrace frame:
     - ip: instruction pointer
     - fp: frame pointer
     - nargs: number of arguments

    Return a BacktraceFrame object.
    """
    frame = BacktraceFrame(ip)
    address = fp + CPU_WORD_SIZE
    try:
        for index in xrange(nargs):
            address += CPU_WORD_SIZE
            word = process.readWord(address)
            frame.arguments.append(word)
    except PtraceError:
        # Ignore argument read error
        pass
    return frame

