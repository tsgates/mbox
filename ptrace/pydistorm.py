"""
:[diStorm64 1.7.27}:
Copyright RageStorm (C) 2007, Gil Dabah

diStorm is licensed under the BSD license.
http://ragestorm.net/distorm/
---
Python binding of diStorm64 library written by Victor Stinner
"""

from ctypes import cdll, c_long, c_ulong, c_int, c_uint, c_char, POINTER, Structure, addressof, byref, c_void_p, create_string_buffer, sizeof, cast
from ptrace.six import binary_type

# Define (u)int32_t and (u)int64_t types
int32_t = c_int
uint32_t = c_uint
if sizeof(c_ulong) == 8:
    int64_t = c_long
    uint64_t = c_ulong
else:
    from ctypes import c_longlong, c_ulonglong
    assert sizeof(c_longlong) == 8
    assert sizeof(c_ulonglong) == 8
    int64_t = c_longlong
    uint64_t = c_ulonglong

SUPPORT_64BIT_OFFSET = True
if SUPPORT_64BIT_OFFSET:
    _OffsetType = uint64_t
else:
    _OffsetType = uint32_t

LIB_FILENAME = 'libdistorm64.so'
distorm = cdll.LoadLibrary(LIB_FILENAME)
Decode16Bits = 0
Decode32Bits = 1
Decode64Bits = 2
DECODERS = (Decode16Bits, Decode32Bits, Decode64Bits)

internal_decode = distorm.internal_decode

DECRES_NONE = 0
DECRES_SUCCESS = 1
DECRES_MEMORYERR = 2
DECRES_INPUTERR = 3

MAX_INSTRUCTIONS = 100
MAX_TEXT_SIZE = 60

class _WString(Structure):
    _fields_ = (
        ("pos", c_uint),
        ("p", c_char * MAX_TEXT_SIZE),
    )
    def __str__(self):
        # FIXME: Use pos?
        return self.p

class _DecodedInst(Structure):
    _fields_ = (
        ("mnemonic", _WString),
        ("operands", _WString),
        ("instructionHex", _WString),
        ("size", c_uint),
        ("offset", _OffsetType),
    )
    def __str__(self):
        return "%s %s" % (self.mnemonic, self.operands)

internal_decode.argtypes = (_OffsetType, c_void_p, c_int, c_int, c_void_p, c_uint, POINTER(c_uint))

def Decode(codeOffset, code, dt=Decode32Bits):
    """
    Errors: TypeError, IndexError, MemoryError, ValueError
    """
    # Check arguments
    if not isinstance(codeOffset, (int, long)):
        raise TypeError("codeOffset have to be an integer")
    if not isinstance(code, binary_type):
        raise TypeError("code have to be a %s, not %s"
                        % (binary_type.__name__, type(code).__name__))
    if dt not in DECODERS:
        raise IndexError("Decoding-type must be either Decode16Bits, Decode32Bits or Decode64Bits.")

    # Allocate memory for decoder
    code_buffer = create_string_buffer(code)
    decodedInstructionsCount = c_uint()
    result = create_string_buffer(sizeof(_DecodedInst)*MAX_INSTRUCTIONS)

    # Prepare arguments
    codeLen = len(code)
    code = addressof(code_buffer)
    while codeLen:
        # Call internal decoder
        res = internal_decode(codeOffset, code, codeLen, dt, result, MAX_INSTRUCTIONS, byref(decodedInstructionsCount))

        # Check for errors
        if res == DECRES_INPUTERR:
            raise ValueError("Invalid argument")
        count = decodedInstructionsCount.value
        if res == DECRES_MEMORYERR and not count:
            raise MemoryError()

        # No more instruction
        if not count:
            break

        # Yield instruction and compute decoded size
        size = 0
        instr_array = cast(result, POINTER(_DecodedInst))
        for index in xrange(count):
            instr = instr_array[index]
            size += instr.size
            yield instr

        # Update parameters to move to next instructions
        code += size
        codeOffset += size
        codeLen -= size

