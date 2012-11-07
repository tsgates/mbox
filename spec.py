
import os
import stat
import errno

from util import *

#
# syscall : (ret, arg0, arg1, arg2, ...)
#
# ([name:]type)
#  - if name is not speficied, type.split("_")[1] will be name
#  - arg# also aliased
#  
SYSCALLS = {
  "open"   : ("f_fd" , "f_path"      , "f_flag" , "f_mode") ,
  "openat" : ("f_fd" , "dirfd:at_fd" , "f_path" , "f_flag"  , "f_mode") ,
  "close"  : ("err"  , "f_fd")       ,
}

class Syscall:
    def __init__(self, sc):
        self.sc   = sc
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
        r  = ("rdi", "rsi", "rdx", "r10", "r8", "r9")[seq]
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
        pass    

    def __restore_int(self, proc, new):
        pass    

class err(arg):
    argtype = "int"
    def __init__(self, arg, syscall):
        self.err = arg
    def __str__(self):
        if self.err == 0:
            return "ok"
        return "%s" % errno.errorcode[-self.err]

class f_fd(arg):
    argtype = "int"
    def __init__(self, arg, syscall):
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
    def __init__(self, arg, syscall):
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
        return chjoin(root, cwd[1:], pn[1:])
    
    def __str__(self):
        return "%s%s" % (self.path, "" if exists(self.path) else " (N)")

class f_flag(arg):
    argtype = "int"
    def __init__(self, arg, syscall):
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
    def __init__(self, arg, syscall):
        self.mode = None
        if syscall.flag.chk(O_CREAT):
            self.mode = arg
    def __str__(self):
        if self.mode is None:
            return "-"
        return "0%o" % self.mode
    
AT_FDCWD = (MAX_INT - 100)

class at_fd(f_fd):
    def __init__(self, arg, syscall):
        super(at_fd, self).__init__(arg, syscall)
    def __str__(self):
        if self.fd == AT_FDCWD:
            return "AT_FDCWD"
        return super(at_fd, self).__str__()