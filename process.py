import os

from ptrace  import *
from syscall import *

def run(args):
    pid = os.fork()
    
    # child
    if pid == 0:
        ptrace_traceme()
        os.execvp(args[0], args)
        print "Failed to execute: %s" % " ".join(args)
        exit(1)
    # parent
    else:
        (pid, status) = os.wait()

        # set to follow children
        ptrace(PTRACE_SETOPTIONS, pid, 0,
               PTRACE_O_TRACESYSGOOD    # SIGTRAP|0x80 if syscall call traps
               | PTRACE_O_TRACEFORK     # PTRACE_EVENT_FORK
               | PTRACE_O_TRACEVFORK    # PTRACE_EVENT_VFORK
               | PTRACE_O_TRACECLONE    # PTRACE_EVENT_CLONE
               | PTRACE_O_TRACEEXEC     # PTRACE_EVENT_EXEC
               | PTRACE_O_TRACEEXIT)    # PTRACE_EVENT_EXIT

        # interpose next syscall
        ptrace_syscall(pid)
        
    return pid

PS_ENTERING = 0
PS_EXITING  = 1

class Process(object):
    def __init__(self, pid):
        self.gen   = 0
        self.pid   = pid
        self.state = PS_ENTERING
        self.sc    = None
        self.regs  = (-1, None)
    
    def syscall(self):
        # new syscall
        self.gen += 1
        
        # new syscall
        if self.sc is None or self.sc.exiting:
            self.sc = Syscall(self)
        else:
            self.sc.update()
        return self.sc

    def getregs(self):
        if self.regs[0] != self.gen:
            regs = ptrace_getregs(self.pid)
            self.regs = (self.gen, regs)
        return self.regs[1]

    def getreg(self, regname):
        regs = self.getregs()
        return getattr(regs, regname)

    def setregs(self, regs):
        return ptrace_setregs(self.pid, regs)

    def setreg(self, regname, value):
        regs = self.getregs()
        setattr(regs, regname, value)
        ptrace_setregs(self.pid, regs)

    def peek(self, addr):
        return ptrace_peek(self.pid, addr)

    def poke(self, addr, word):
        return ptrace_poke(self.pid, addr, word)
    
    def read_bytes(self, ptr, size):
        data = b''
        WORD = 8
        offset = ptr % WORD
        if offset:
            # read word
            ptr -= offset
            blob = self.peek(ptr)

            # read some bytes from the word
            subsize = min(WORD - offset, size)
            data = blob[offset:offset+subsize]

            # move cursor
            size -= subsize
            ptr += WORD
            
        while size:
            # read word
            blob = self.peek(ptr)

            # read bytes from the word
            if size < WORD:
                data += blob[:size]
                break
            data += blob

            # move cursor
            size -= WORD
            ptr += WORD
            
        return data

    def read_str(self, ptr, limit=1024):
        rtn = []
        WORD = 8
        while len(rtn) < limit:
            blob = self.peek(ptr)
            null = blob.find(b'\0')
            # done
            if null != -1:
                rtn.extend(blob[:null])
                break
            rtn.extend(blob)
            ptr += WORD
        return ''.join(rtn)

    def write_bytes(self, ptr, blob):
        # off
        # [..bb]...[ee..]
        #    ^        ^
        #    +-- ptr  |
        # [byte]      |
        #             rear
        #             
        WORD = 8

        # adjust front bytes
        off = ptr % WORD
        if off:
            ptr  = ptr - off
            byte = self.peek(ptr)
            blob = byte[:off] + blob

        # adjust rear bytes
        rear = ptr + len(blob)
        off = rear % WORD
        if off:
            byte = self.peek(rear - off)
            blob = blob + byte[off:]

        assert len(blob) % WORD == 0

        # write
        for i in range(0, len(blob), WORD):
            self.poke(ptr + i, byte2word(blob[i:i+WORD]))

    def write_str(self, ptr, blob):
        self.write_bytes(ptr, blob + '\x00')
