
import os
from os.path import *

MAX_PATH = 256

O_ACCMODE  = 00000003
O_RDONLY   = 00000000
O_WRONLY   = 00000001
O_RDWR     = 00000002
O_CREAT    = 00000100	# not fcntl 
O_EXCL     = 00000200	# not fcntl 
O_NOCTTY   = 00000400	# not fcntl 
O_TRUNC    = 00001000	# not fcntl 
O_APPEND   = 00002000
O_NONBLOCK = 00004000
O_DSYNC    = 00010000	# used to be O_SYNC, see below 
O_DIRECT   = 00040000	# direct disk access hint 
O_LARGEFILE= 00100000
O_DIRECTORY= 00200000	# must be a directory
O_NOFOLLOW = 00400000	# don't follow links
O_NOATIME  = 01000000
O_CLOEXEC  = 02000000	# set close_on_exec

class f_path:
    def __init__(self, path):
        self.path = path
        
    def escaped(self, pn, root):
        # escaped by multiple ..
        if not pn.startswith(root):
            return root
        return pn
    
    def chroot(self, root, cwd):
        pn = normpath(self.path)
        # absolute path
        if pn.startswith("/"):
            pn = normpath(join(root, pn[1:]))
            return self.escaped(pn, root)
        # cwd
        assert cwd.startswith(root)
        pn = normpath(join(cwd, pn))
        return self.escaped(pn, root)
    
    def __str__(self):
        exist = os.path.exists(self.path)
        return "%s%s" % (self.path, "" if exist else " (N)")

class f_flag:
    def __init__(self, flag):
        self.flag = flag
    def is_rdonly(self):
        return (self.flag & O_ACCMODE) == O_RDONLY
    def is_wronly(self):
        return (self.flag & O_ACCMODE) == O_WRONLY
    def is_rdwr(self):
        return (self.flag & O_ACCMODE) == O_RDWR
    def chk(self, f):
        return self.flag & f
    def __str__(self):
        rtn = []
        for f in ["O_RDONLY", "O_WRONLY", "O_RDWR"]:
            if self.flag & O_ACCMODE == eval(f):
                rtn.append(f)
        
        for f in ["O_CREAT", "O_EXCL", "O_NOCTTY",
                  "O_TRUNC", "O_APPEND", "O_NONBLOCK",
                  "O_DSYNC", "O_DIRECT", "O_LARGEFILE",
                  "O_DIRECTORY", "O_NOFOLLOW", "O_NOATIME",
                  "O_CLOEXEC"]:
            if self.flag & eval(f) != 0:
                rtn.append(f)

        return "|".join(rtn)
    
class f_mode:
    def __init__(self, mode, flag):
        self.mode = None
        if flag.chk(O_CREAT):
            self.mode = mode
    def __str__(self):
        if self.mode is None:
            return "-"
        return "0%o" % self.mode
        
       
