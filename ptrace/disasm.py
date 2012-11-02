"""
Disassembler: only enabled if HAS_DISASSEMBLER is True.
"""

try:
    from ptrace.cpu_info import CPU_I386, CPU_X86_64
    try:
        from distorm3 import Decode
        if CPU_X86_64:
            from distorm3 import Decode64Bits as DecodeBits
            MAX_INSTR_SIZE = 11
        elif CPU_I386:
            from distorm3 import Decode32Bits as DecodeBits
            MAX_INSTR_SIZE = 8
        else:
            raise ImportError("CPU not supported")
        DISTORM3 = True
    except ImportError, err:
        DISTORM3 = False
        from ptrace.pydistorm import Decode
        if CPU_X86_64:
            from ptrace.pydistorm import Decode64Bits as DecodeBits
            MAX_INSTR_SIZE = 11
        elif CPU_I386:
            from ptrace.pydistorm import Decode32Bits as DecodeBits
            MAX_INSTR_SIZE = 8
        else:
            raise ImportError("CPU not supported")
    from ptrace import PtraceError

    class Instruction(object):
        """
        A CPU instruction.

        Attributes:
         - address (int): address of the instruction
         - size (int): size of the instruction in bytes
         - mnemonic (str): name of the instruction
         - operands (str): string describing the operands
         - hexa (str): bytes of the instruction as an hexadecimal string
         - text (str): string representing the whole instruction
        """
        def __init__(self, instr):
            if DISTORM3:
                self.address, self.size, self.text, self.hexa = instr
            else:
                self.address = instr.offset
                self.size = instr.size
                self.hexa = unicode(instr.instructionHex)
                self.text = u"%s %s" % (instr.mnemonic, instr.operands)

        def __str__(self):
            return self.text

    def disassemble(code, address=0x100):
        """
        Disassemble the specified byte string, where address is the
        address of the first instruction.
        """
        for instr in Decode(address, code, DecodeBits):
            yield Instruction(instr)

    def disassembleOne(code, address=0x100):
        """
        Disassemble the first instruction of the byte string, where
        address is the address of the instruction.
        """
        for instr in disassemble(code, address):
            return instr
        raise PtraceError("Unable to disassemble %r" % code)

    HAS_DISASSEMBLER = True
except (ImportError, OSError), err:
    # OSError if libdistorm64.so doesn't exist
    HAS_DISASSEMBLER = False

