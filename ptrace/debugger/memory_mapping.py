from ptrace.os_tools import HAS_PROC
if HAS_PROC:
     from ptrace.linux_proc import openProc, ProcError
from ptrace.debugger.process_error import ProcessError
from ptrace.ctypes_tools import formatAddress
import re
from weakref import ref

PROC_MAP_REGEX = re.compile(
    # Address range: '08048000-080b0000 '
    r'([0-9a-f]+)-([0-9a-f]+) '
    # Permission: 'r-xp '
    r'(.{4}) '
    # Offset: '0804d000'
    r'([0-9a-f]+) '
    # Device (major:minor): 'fe:01 '
    r'([0-9a-f]{2}):([0-9a-f]{2}) '
    # Inode: '3334030'
    r'([0-9]+)'
    # Filename: '  /usr/bin/synergyc'
    r'(?: +(.*))?')

class MemoryMapping(object):
    """
    Process memory mapping (metadata about the mapping).

    Attributes:
     - start (int): first byte address
     - end (int): last byte address + 1
     - permissions (str)
     - offset (int): for file, offset in bytes from the file start
     - major_device / minor_device (int): major / minor device number
     - inode (int)
     - pathname (str)
     - _process: weak reference to the process

    Operations:
     - "address in mapping" checks the address is in the mapping.
     - "search(somestring)" returns the offsets of "somestring" in the mapping
     - "str(mapping)" create one string describing the mapping
     - "repr(mapping)" create a string representation of the mapping,
       useful in list contexts
    """
    def __init__(self, process, start, end, permissions, offset, major_device, minor_device, inode, pathname):
        self._process = ref(process)
        self.start = start
        self.end = end
        self.permissions = permissions
        self.offset = offset
        self.major_device = major_device
        self.minor_device = minor_device
        self.inode = inode
        self.pathname = pathname

    def __contains__(self, address):
        return self.start <= address < self.end

    def __str__(self):
        text = "%s-%s" % (formatAddress(self.start), formatAddress(self.end))
        if self.pathname:
            text += " => %s" % self.pathname
        text += " (%s)" % self.permissions
        return text
    __repr__ = __str__

    def search(self, bytestr):
        process = self._process()

        bytestr_len = len(bytestr)
        buf_len = 64 * 1024 

        if buf_len < bytestr_len:
            buf_len = bytestr_len

        remaining = self.end - self.start
        covered = self.start

        while remaining >= bytestr_len:
            if remaining > buf_len:
                requested = buf_len
            else:
                requested = remaining

            data = process.readBytes(covered, requested)

            if data == "":
                break

            offset = data.find(bytestr)
            if (offset == -1):
                skip = requested - bytestr_len + 1
            else:
                yield (covered + offset)
                skip = offset + bytestr_len

            covered += skip
            remaining -= skip

def readProcessMappings(process):
    """
    Read all memory mappings of the specified process.

    Return a list of MemoryMapping objects, or empty list if it's not possible
    to read the mappings.

    May raise a ProcessError.
    """
    maps = []
    if not HAS_PROC:
        return maps
    try:
        mapsfile = openProc("%s/maps" % process.pid)
    except ProcError, err:
        raise ProcessError(process, "Unable to read process maps: %s" % err)
    try:
        for line in mapsfile:
            line = line.rstrip()
            match = PROC_MAP_REGEX.match(line)
            if not match:
                raise ProcessError(process, "Unable to parse memoy mapping: %r" % line)
            map = MemoryMapping(
                process,
                int(match.group(1), 16),
                int(match.group(2), 16),
                match.group(3),
                int(match.group(4), 16),
                int(match.group(5), 16),
                int(match.group(6), 16),
                int(match.group(7)),
                match.group(8))
            maps.append(map)
    finally:
        mapsfile.close()
    return maps

