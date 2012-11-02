"""
Define standard (integers) types.

Signed types:
 - int8_t
 - int16_t
 - int32_t
 - int64_t
 - size_t

Unsigned types:
 - uint8_t
 - uint16_t
 - uint32_t
 - uint64_t
"""

from ctypes import sizeof, \
    c_byte, c_ubyte, \
    c_short, c_ushort, \
    c_int, c_uint, \
    c_long, c_ulong, \
    c_longlong, c_ulonglong

# 8-bit integers
uint8_t = c_ubyte
int8_t = c_byte

# 16-bit integers
assert sizeof(c_short) == 2
assert sizeof(c_ushort) == 2
int16_t = c_short
uint16_t = c_ushort

# 32-bit integers
assert sizeof(c_int) == 4
assert sizeof(c_uint) == 4
int32_t = c_int
uint32_t = c_uint

# 64-bit integers
if sizeof(c_long) == 8:
    int64_t = c_long
else:
    assert sizeof(c_longlong) == 8
    int64_t = c_longlong
if sizeof(c_ulong) == 8:
    uint64_t = c_ulong
else:
    assert sizeof(c_ulonglong) == 8
    uint64_t = c_ulonglong

# size_t
size_t = c_long

__all__ = (
    "uint8_t", "int8_t", "int16_t", "uint16_t",
    "int32_t", "uint32_t", "int64_t", "uint64_t", "size_t")
