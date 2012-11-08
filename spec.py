
import os
import stat
import errno
import struct
import dbg

from util import *

#
# syscall : (ret, arg0, arg1, arg2, ...)
#
# ([name:]type)
#  - if name is not speficied, type.split("_")[1] will be name
#  - arg# also aliased
#
SYSCALLS = {
  "open"     : ("f_fd" , "f_path"      , "f_flag" , "f_mode"             ),
  "openat"   : ("f_fd" , "dirfd:at_fd" , "f_path" , "f_flag"  , "f_mode" ),
  "close"    : ("err"  , "f_fd"                                          ),
  "getdents" : ("f_len", "f_fd"        , "f_dirp" , "f_size"             ),
  "stat"     : ("err"  , "f_path"      , "f_statp"                       ),
  "fstat"    : ("err"  , "f_fd"        , "f_statp"                       ),
  "fstatat"  : ("err"  , "dirfd:at_fd" , "f_path" , "f_statp" , "f_int"  ),
  "lstat"    : ("err"  , "f_path"      , "f_statp"                       ),
  "unlink"   : ("err"  , "f_path"                                        ),
  "unlinkat" : ("err"  , "dirfd:at_fd" , "f_path" , "f_int"              ),
  "getxattr" : ("serr" , "f_path"      , "f_cstr" , "f_ptr"   , "f_int"  ),
  "access"   : ("err"  , "f_path"      , "f_int"                         ),
  "faccessat": ("err"  , "dirfd:at_fd" , "f_path" , "f_int"              ),
}

# XXX.
# 188     common  setxattr                sys_setxattr
# 189     common  lsetxattr               sys_lsetxattr
# 190     common  fsetxattr               sys_fsetxattr
# 191     common  getxattr                sys_getxattr
# 192     common  lgetxattr               sys_lgetxattr
# 193     common  fgetxattr               sys_fgetxattr
# 194     common  listxattr               sys_listxattr
# 195     common  llistxattr              sys_llistxattr
# 196     common  flistxattr              sys_flistxattr
# 197     common  removexattr             sys_removexattr
# 198     common  lremovexattr            sys_lremovexattr
# 199     common  fremovexattr            sys_fremovexattr

# newstat
for sc in ["stat", "fstat", "lstat", "fstatat"]:
    SYSCALLS["new" + sc] = SYSCALLS.get(sc, [])

class Syscall:
    def __init__(self, sc):
        self.sc   = sc
        self.proc = sc.process
        self.name = sc.name
        self.args = []
        self.ret  = None

        # for args
        args = SYSCALLS.get(self.name, [])
        for (i, arg) in enumerate(args[1:]):
            (name, kls) = self.__parse_syscall(arg)
            val = self.__parse_arg(self.sc, kls, i)

            # alias: arg#, name, args
            setattr(self, "arg%d" % i, val)
            setattr(self, name, val)
            self.args.append(val)

        # for ret
        if self.sc.is_exit():
            (name, kls) = self.__parse_syscall(args[0])
            val = self.__parse_ret(self.sc, kls)

            setattr(self, "ret", val)
            setattr(self, name, val)

    def __parse_syscall(self, arg):
        kls  = arg
        name = None
        if ":" in arg:
            (name, kls) = arg.split(":")
        else:
            if "_" in kls:
                name = kls.split("_")[1]
            else:
                name = kls
        return (name, eval(kls))

    def __parse_arg(self, sc, kls, seq):
        arg = None
        if kls.argtype == "str":
            arg = sc.getArgString
        elif kls.argtype == "int":
            arg = sc.getArg
        else:
            raise Exception("Not implemented yet")
        return newarg(kls, arg(seq), seq, self)

    def __parse_ret(self, sc, kls):
        assert kls.argtype == "int"
        return newarg(kls, sc.result, -1, self)

    def __str__(self):
        pid = self.sc.process.pid
        seq = ">" if self.sc.is_enter() else "<"
        rtn = "[%d]%s %s(%s)" % (pid, seq, self.name, ",".join(str(a) for a in self.args))
        if self.sc.is_exit():
            rtn += " = %s" % str(self.ret)
        return rtn

#
# weave functions for arguments
#  - don't like super() in python, so weave here
#
def newarg(kls, arg, seq, sc):
    val = kls(arg, sc)
    setattr(val, kls.argtype, arg)
    setattr(val, "seq", seq)
    setattr(val, "old", None)
    return val

class arg(object):
    def hijack(self, proc, new):
        if self.argtype == "str":
            self.__hijack_str(proc, new)
        elif self.argtype == "int":
            self.__hijack_int(proc, new)

    def restore(self, proc, new):
        if self.argtype == "str":
            self.__restore_str(proc, new)
        elif self.argtype == "int":
            self.__restore_int(proc, new)

    def __get_arg(self, proc, seq):
        r  = ("rdi", "rsi", "rdx", "r10", "r8", "r9", "rax")[seq]
        regs = proc.getregs()
        return (r, getattr(regs, r))

    def __hijack_str(self, proc, new):
        assert type(new) is str and len(new) < MAX_PATH - 1

        # memcpy to the lower part of stack
        ptr = proc.getStackPointer() - MAX_PATH
        proc.writeBytes(ptr, new + "\x00")

        # write to the proper register
        (reg, self.old) = self.__get_arg(proc, self.seq)
        proc.setreg(reg, ptr)

    def __restore_str(self, proc, new):
        assert type(new) is str
        (reg, _) = self.__get_arg(proc, self.seq)
        proc.setreg(reg, self.old)

    def __hijack_int(self, proc, new):
        assert type(new) is int
        (reg, self.old) = self.__get_arg(proc, self.seq)
        proc.setreg(reg, new)

    def __restore_int(self, proc, new):
        assert type(new) is int
        (reg, _) = self.__get_arg(proc, self.seq)
        proc.setreg(reg, self.old)

class err(arg):
    argtype = "int"
    def __init__(self, arg, sc):
        self.arg = arg
    def ok(self):
        return self.arg == 0
    def err(self):
        return self.arg != 0
    def restore(self, proc, new):
        if self.int != new:
            self.old = new
            self.__restore_int(proc, new)
    def __str__(self):
        if self.ok():
            return "ok"
        return "%s" % errno.errorcode[-self.arg]

class serr(err):
    argtype = "int"
    def __init__(self, arg, sc):
        super(serr, self).__init__(arg, sc)
    def ok(self):
        return self.arg >= 0
    def err(self):
        return self.arg < 0

class ptr(arg):
    def __init__(self, arg, sc):
        self.ptr = arg
    def __str__(self):
        return "0x%x" % self.ptr

class f_int(arg):
    argtype = "int"
    def __init__(self, arg, sc):
        self.arg = arg
    def __str__(self):
        return "%d" % self.arg

f_size = f_int
f_len  = f_int

class f_ptr(ptr):
    argtype = "int"
    def __init__(self, arg, sc):
        super(f_ptr, self).__init__(arg, sc)

class f_cstr(arg):
    argtype = "str"
    def __init__(self, arg, sc):
        self.arg = arg
    def __str__(self):
        return "%s" % self.arg

class f_dirp(ptr):
    argtype = "int"
    def __init__(self, arg, sc):
        super(f_dirp, self).__init__(arg, sc)
        self.sc = sc

    def hijack(self, proc, blob):
        raise NotImplemented()

    def restore(self, proc, blob):
        # < alloced memory
        assert len(blob) < self.sc.size.int
        # overwrite buf
        proc.writeBytes(self.ptr, blob)
        # overwrite ret (size of blob)
        proc.setreg("rax", len(blob))

    def read(self):
        assert self.sc.ret
        return self.sc.proc.readBytes(self.ptr, self.sc.ret.int)

class f_fd(arg):
    argtype = "int"
    def __init__(self, arg, sc):
        self.fd = arg
    def err(self):
        return self.fd < 0
    def __str__(self):
        if self.fd >= 0:
            return "%d" % self.fd
        return "%s" % errno.errorcode[-self.fd]

#
# specifications
#

MAX_INT  = 2**64
MAX_PATH = 256

O_ACCMODE  = 00000003
O_RDONLY   = 00000000
O_WRONLY   = 00000001
O_RDWR     = 00000002
O_CREAT    = 00000100   # create file if it does not exist
O_EXCL     = 00000200   # error if create and file exists
O_NOCTTY   = 00000400   #
O_TRUNC    = 00001000   # truncate size to 0
O_APPEND   = 00002000   # append when writing
O_NONBLOCK = 00004000   # non-blocking
O_DSYNC    = 00010000   # used to be O_SYNC, see below
O_DIRECT   = 00040000   # direct disk access hint
O_LARGEFILE= 00100000
O_DIRECTORY= 00200000   # must be a directory
O_NOFOLLOW = 00400000   # don't follow links
O_NOATIME  = 01000000   # no access time
O_CLOEXEC  = 02000000   # set close_on_exec

class f_path(arg):
    argtype = "str"
    def __init__(self, arg, sc):
        self.path = arg

    def exists(self):
        return exists(self.path)

    def is_dir(self):
        return dir_exists(self.path)

    def normpath(self, cwd):
        pn = normpath(self.path)
        if pn.startswith("/"):
            return pn
        else:
            return join(cwd, pn)

    def chroot(self, root, cwd):
        pn = normpath(self.path)
        # absolute path
        if pn.startswith("/"):
            return chjoin(root, pn[1:])
        # cwd
        assert cwd.startswith("/")
        return chjoin(root, cwd[1:], pn)

    def __str__(self):
        return "%s%s" % (self.path, "" if exists(self.path) else "(N)")

class f_flag(arg):
    argtype = "int"
    def __init__(self, arg, sc):
        self.flag = arg
    def is_rdonly(self):
        return (self.flag & O_ACCMODE) == O_RDONLY
    def is_wronly(self):
        return (self.flag & O_ACCMODE) == O_WRONLY
    def is_rdwr(self):
        return (self.flag & O_ACCMODE) == O_RDWR
    def is_wr(self):
        return self.is_wronly() or self.is_rdwr()
    def is_trunc(self):
        return (self.flag & O_TRUNC)
    def is_dir(self):
        return (self.flag & O_DIRECTORY)
    def chk(self, f):
        return self.flag & f
    def __str__(self):
        rtn = []
        for f in ["O_RDONLY", "O_WRONLY", "O_RDWR"]:
            if self.flag & O_ACCMODE == eval(f):
                rtn.append(f)

        for f in ["O_CREAT"     , "O_EXCL"     , "O_NOCTTY"    ,
                  "O_TRUNC"     , "O_APPEND"   , "O_NONBLOCK"  ,
                  "O_DSYNC"     , "O_DIRECT"   , "O_LARGEFILE" ,
                  "O_DIRECTORY" , "O_NOFOLLOW" , "O_NOATIME"   ,
                  "O_CLOEXEC"]:
            if self.flag & eval(f) != 0:
                rtn.append(f)

        return "|".join(rtn)

class f_mode(arg):
    argtype = "int"
    def __init__(self, arg, sc):
        self.mode = None
        if sc.flag.chk(O_CREAT):
            self.mode = arg
    def __str__(self):
        if self.mode is None:
            return "-"
        return "0%o" % self.mode

AT_FDCWD = (MAX_INT - 100)

class at_fd(f_fd):
    def __init__(self, arg, sc):
        super(at_fd, self).__init__(arg, sc)
    def __str__(self):
        if self.fd == AT_FDCWD:
            return "AT_FDCWD"
        return super(at_fd, self).__str__()

class f_statp(ptr):
    argtype = "int"
    def __init__(self, arg, sc):
        super(f_statp, self).__init__(arg, sc)
        self.sc = sc

#
# dirents related
#
def parse_dirents(blob):
    rtn = []
    off = 0
    while off < len(blob):
        d = dirent()
        d.parse(blob, off)
        rtn.append(d)
        off += d.d_reclen
    return rtn

def get_dirents(path):
    #
    # NOTE. slow, call getdirent() syscall intead
    #
    rtn = []
    off = 1
    for f in os.listdir(path):
        s = os.stat(join(path, f))
        d = dirent()
        d.d_name   = f
        d.d_type   = __st_to_dt(s)
        d.d_ino    = s.st_ino
        d.d_off    = off
        d.d_reclen = ((len(f)+19+24)/24)*24
        rtn.append(d)
        off += 1
    return rtn

DT_UNKNOWN = 0  # The file type is unknown
DT_FIFO    = 1  # This is a named pipe (FIFO)
DT_CHR     = 2  # This is a character device
DT_DIR     = 4  # This is a directory
DT_BLK     = 6  # This is a block device
DT_REG     = 8  # This is a regular file
DT_LNK     =10  # This is a symbolic link
DT_SOCK    =14  # This is a UNIX domain socket

def __st_to_dt(s):
    mod = s.st_mode
    for m in ["BLK", "CHR", "DIR", "FIFO", "LNK", "REG", "SOCK"]:
        if getattr(stat, "S_IS" + m)(mod):
            rtn = eval("DT_" + m)
            break
    return rtn

#
# NOTE.
#  - d_off seems to be ignored in everywhere
#    tmpfs sets the order of dirent to d_off
#  - d_reclen seems to be aligned 24, so I abide by too
#
class dirent:
    fields = [("d_ino"   , "<Q"),
              ("d_off"   , "<Q"),
              ("d_reclen", "<H")]

    def __init__(self):
        for (field, fmt) in dirent.fields:
            setattr(self, field, None)
        self.d_name = ""
        self.d_type = DT_UNKNOWN

    def parse(self, buf, beg):
        offset = beg
        for (field, fmt) in dirent.fields:
            val = struct.unpack_from(fmt, buf, offset)
            setattr(self, field, val[0])
            dbg.dirent(field, "%x" % offset, "val=", getattr(self, field))
            offset += struct.calcsize(fmt)

        self.d_name = buf[offset:beg + self.d_reclen - 1].rstrip("\x00")
        self.d_type = ord(buf[beg + self.d_reclen - 1])

        dbg.dirent("offset:%x, '%s'(%d)" % (offset, self.d_name, len(self.d_name)))

    def pack(self):
        # regular header
        blob = ""
        for (field, fmt) in dirent.fields:
            blob += struct.pack(fmt, getattr(self, field))
        # name:char[]
        blob += self.d_name
        # padding
        blob += "\x00" * (self.d_reclen - len(blob) - 1)
        # type
        blob += chr(self.d_type)
        return blob

    def __str__(self):
        return "%d(offset:%d, len:%d): %s (type:%s)" \
          % (self.d_ino, self.d_off, self.d_reclen, self.d_name, self.d_type)
