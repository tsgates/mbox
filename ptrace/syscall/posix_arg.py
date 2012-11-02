from ptrace.tools import readBits, formatBits
from ptrace.signames import signalName

# From /usr/include/bits/mman.h (Ubuntu Feisty, i386)
MMAP_PROT_BITMASK = (
    (1, "PROT_READ"),
    (2, "PROT_WRITE"),
    (4, "PROT_EXEC"),
    (0x01000000, "PROT_GROWSDOWN"),
    (0x02000000, "PROT_GROWSUP"),
)

def formatMmapProt(argument):
    return formatBits(argument.value, MMAP_PROT_BITMASK, "PROT_NONE")

# From /usr/include/bits/mman.h (Ubuntu Feisty, i386)
ACCESS_MODE_BITMASK = (
    (1, "X_OK"),
    (2, "W_OK"),
    (4, "R_OK"),
)

def formatAccessMode(argument):
    return formatBits(argument.value, ACCESS_MODE_BITMASK, "F_OK")

# From /usr/include/bits/fcntl.h (Ubuntu Feisty, i386)
OPEN_MODE_BITMASK = (
    (01, "O_WRONLY"),
    (02, "O_RDWR"),
    (0100, "O_CREAT"),
    (0200, "O_EXCL"),
    (0400, "O_NOCTTY"),
    (01000, "O_TRUNC"),
    (02000, "O_APPEND"),
    (04000, "O_NONBLOCK"),
    (010000, "O_SYNC"),
    (020000, "O_ASYNC"),
    (040000, "O_DIRECT"),
    (0100000, "O_LARGEFILE"),
    (0200000, "O_DIRECTORY"),
    (0400000, "O_NOFOLLOW"),
    (01000000, "O_NOATIME"),
)

def formatOpenMode(argument):
    return formatBits(int(argument.value), OPEN_MODE_BITMASK, "O_RDONLY", oct)

CLONE_FLAGS_BITMASK = (
    (0x00000100, "CLONE_VM"),
    (0x00000200, "CLONE_FS"),
    (0x00000400, "CLONE_FILES"),
    (0x00000800, "CLONE_SIGHAND"),
    (0x00002000, "CLONE_PTRACE"),
    (0x00004000, "CLONE_VFORK"),
    (0x00008000, "CLONE_PARENT"),
    (0x00010000, "CLONE_THREAD"),
    (0x00020000, "CLONE_NEWNS"),
    (0x00040000, "CLONE_SYSVSEM"),
    (0x00080000, "CLONE_SETTLS"),
    (0x00100000, "CLONE_PARENT_SETTID"),
    (0x00200000, "CLONE_CHILD_CLEARTID"),
    (0x00400000, "CLONE_DETACHED"),
    (0x00800000, "CLONE_UNTRACED"),
    (0x01000000, "CLONE_CHILD_SETTID"),
    (0x02000000, "CLONE_STOPPED"),
    (0x04000000, "CLONE_NEWUTS"),
    (0x08000000, "CLONE_NEWIPC"),
)

def formatCloneFlags(argument):
    flags = argument.value
    bits = readBits(flags, CLONE_FLAGS_BITMASK)
    signum = flags & 0xFF
    if signum:
        bits.insert(0, signalName(signum))
    if bits:
        bits = "%s" % ("|".join(bits))
        return "<%s> (%s)" % (bits, str(flags))
    else:
        return str(flags)

