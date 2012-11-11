import os
import dbg
import pprint

from spec import *
from util import *

#
# redirect to f[func]at-like function (dirfd-relative syscall)
#
def redirect_at(func):
    def new(self, proc, sc):
        sc.dirfd = at_fd(AT_FDCWD, sc)
        at = func.__name__.replace("_", "at_")
        for f in [at, "f"+at]:
            if hasattr(self, f):
                funcat = getattr(self, f)
                break
        return funcat(proc, sc)
    return new

# flag to control path rewriting
RW_WRITING = 1
RW_FORCE   = 2
RW_NONE    = 3

class OS:
    def __init__(self, root, cwd):
        #
        # cwd    in hostfs
        # dirfd  in sandboxfs
        # filefd in hostfs|sandboxfs
        #
        self.root    = root.rstrip("/")   # root dir of sandboxfs
        self.fds     = defaultdict(dict)  # fd->path (normalized, original)
        self.cwd     = cwd                # initial cwd
        self.cwds    = {}                 # cwd of each process
        self.stat    = defaultdict(int)   # statistics of syscalls
        self.dirents = defaultdict(dict)  # state (seek equivalent)
        self.deleted = defaultdict(set)   # fullpath -> set of filenames

        # rewriting tasks
        self.hijack = []

        # init root
        mkdir(self.root)

    #
    # main driver
    #
    def run(self, proc, syscall):
        if syscall.is_enter():
            assert len(self.hijack) == 0
            self.stat[syscall.name] += 1

        cond = "enter" if syscall.is_enter() else "exit"
        func = "%s_%s" % (syscall.name, cond)
        if hasattr(self, func):
            sc = Syscall(syscall)
            dbg.ns(sc)
            getattr(self, func)(proc, sc)

        if syscall.is_enter():
            for (arg, new) in self.hijack:
                dbg.ns(" -> %s", new)
                arg.hijack(proc, new)
        else:
            for (arg, new) in self.hijack:
                dbg.ns(" <- %s", arg)
                arg.restore(proc, new)
            # clean them up
            self.hijack = []

    def add_hijack(self, arg, new):
        self.hijack.append((arg, new))

    def sync_parent_dirs(self, path):
        for crumb in itercrumb(path):
            spn = join(self.root, crumb[1:])
            if dir_exists(crumb) and not dir_exists(spn):
                mkdir(spn)

    def copy_to(self, pn, spn):
        if file_exists(pn):
            dbg.ns(" copy %s -> %s", pn, spn)
            safecopy(pn, spn)

    def getcwd(self, proc):
        pid = proc.pid
        if pid in self.cwds:
            return self.cwds[proc.pid]
        else:
            # read /proc
            return os.readlink("/proc/%s/cwd" % pid)

    def setcwd(self, proc, path):
        old = self.getcwd(proc)
        self.cwds[proc.pid] = path
        dbg.info(" cwd: %s -> %s" % (old, path))

    def parse_path(self, path, proc):
        return self.parse_path_dirfd(AT_FDCWD, path, proc)

    def parse_path_dirfd(self, dirfd, path, proc):
        if dirfd == AT_FDCWD:
            cwd = self.getcwd(proc)
        else:
            cwd = self.fds[proc.pid][dirfd]
        hpn = path.normpath(cwd)
        spn = path.chroot(self.root, self.getcwd(proc))
        return (hpn, spn)

    def is_deleted(self, hpn):
        (d, f) = os.path.split(hpn)
        return f in self.deleted.get(d, [])

    def put_deleted_file(self, hpn):
        (d, f) = os.path.split(hpn)
        self.deleted[d].add(f)

    # a common way to rewrite host -> sandbox path
    def rewrite_path(self, proc, sc, flag = RW_NONE):
        assert hasattr(sc, "path")
        if hasattr(sc, "dirfd"):
            dirfd = sc.dirfd.fd
        else:
            dirfd = AT_FDCWD

        # fetch host/sandbox path name
        (hpn, spn) = self.parse_path_dirfd(dirfd, sc.path, proc)

        # sync up host/sandbox dir hierarchy
        if not exists(spn) and exists(hpn):
            self.sync_parent_dirs(hpn)

        # hijack pathname:
        #  exist in sandbox  : need to use the file in the sandbox
        #  deleted in sandbox: do not look for the path in the host
        #  will be written   : copy the file and use that file path
        if exists(spn) or self.is_deleted(hpn) or flag != RW_NONE:
            # it has writing intent
            if flag == RW_WRITING:
                self.copy_to(hpn, spn)

            # deletion: we know it will fail in syscall(), but it's correct
            # semantic in terms of correctness
            self.add_hijack(sc.path, spn)
        else:
            # use a file in the host: it could be dangerous
            dbg.info(" use: %s" % sc.path)

    #
    # list of system calls to interleave
    #
    @redirect_at
    def access_enter(self, proc, sc):
        pass

    def faccessat_enter(self, proc, sc):
        self.rewrite_path(proc, sc)

    def chdir_exit(self, proc, sc):
        if sc.ret.ok():
            self.setcwd(proc, sc.path.str)

    def fchdir_exit(self, proc, sc):
        if sc.ret.ok():
            self.setcwd(proc, self.fds[proc.pid][sc.dirfd.fd])

    def getdents_enter(self, proc, sc):
        pass

    def getdents_exit(self, proc, sc):
        pid = proc.pid
        fd  = sc.fd.int

        # exit on current syscall, let's dump hostfs too
        if sc.ret.int == 0:
            state = self.dirents[pid].get(fd, None)
            hpn   = self.fds[pid][fd]
            sdir  = os.listdir(chjoin(self.root, hpn))

            # fetch previous dirents
            if state is None:
                # initial to dump hostfs
                dirents = get_dirents(hpn)
            else:
                dirents = state

            # dump dirents
            blob = ""
            while len(dirents) > 0:
                d = dirents.pop()
                # files exist in the sandbox
                if d.d_name in sdir:
                    continue
                # deleted files
                if self.is_deleted(join(hpn, d.d_name)):
                    continue
                pack = d.pack()
                # need another call to complete
                if len(blob) + len(pack) >= sc.size.int:
                    dirents.append(d)
                    break
                blob += pack

            # reset state
            if state is []:
                self.dirents[pid].get(fd, None)

            # insert blob
            if len(blob) != 0:
                self.add_hijack(sc.dirp, blob)
                self.dirents[pid][fd] = dirents

    def getxattr_enter(self, proc, sc):
        self.rewrite_path(proc, sc)

    @redirect_at
    def open_enter(self, proc, sc):
        pass

    def open_exit(self, proc, sc):
        self.openat_exit(proc, sc)

    def openat_enter(self, proc, sc):
        (hpn, spn) = self.parse_path_dirfd(sc.dirfd.fd, sc.path, proc)

        #
        # XXX. create a virtual layer to simulate /dev, /sys and /proc
        #

        # for dirs
        if (dir_exists(hpn) and sc.flag.is_dir()) or dir_exists(spn):
            # sync parent dir
            self.sync_parent_dirs(hpn)
            # rewrite pn -> spn
            self.add_hijack(sc.path, spn)
            return

        # for files
        if file_exists(spn):
            # rewrite pn -> spn
            self.add_hijack(sc.path, spn)
            return

        # file does not exist in the sandboxfs
        if sc.flag.is_rdonly():
            # safe to read a host pn
            return

        # trunc
        if sc.flag.is_trunc():
            # sync parent dir
            self.sync_parent_dirs(hpn)
            # rewrite pn -> spn
            self.add_hijack(sc.path, spn)
            return

        # read/write
        if sc.flag.is_wr():
            # sync parent dir
            self.sync_parent_dirs(hpn)
            # copy the file to sandbox
            self.copy_to(hpn, spn)
            # rewrite pn -> spn
            self.add_hijack(sc.path, spn)
            return

    def openat_exit(self, proc, sc):
        # keep tracks of open files
        if not sc.ret.err():
            pid = proc.pid
            fd  = sc.ret.int
            cwd = self.getcwd(proc)
            self.fds[pid][fd] = sc.path.normpath(cwd)

    def close_enter(self, proc, sc):
        pass

    def close_exit(self, proc, sc):
        self.fds[proc.pid][sc.fd.int] = None

    @redirect_at
    def stat_enter(self, proc, sc):
        pass

    def stat_exit(self, proc, sc):
        pass

    def fstatat_enter(self, proc, sc):
        self.rewrite_path(proc, sc)

    def newfstatat_enter(self, proc, sc):
        self.fstatat_enter(proc, sc)

    def lstat_enter(self, proc, sc):
        self.stat_enter(proc, sc)

    def lstat_exit(self, proc, sc):
        pass

    @redirect_at
    def unlink_enter(self, proc, sc):
        pass

    @redirect_at
    def unlink_exit(self, proc, sc):
        pass

    def unlinkat_enter(self, proc, sc):
        self.rewrite_path(proc, sc, RW_FORCE)

    def unlinkat_exit(self, proc, sc):
        (hpn, spn) = self.parse_path_dirfd(sc.dirfd.fd, sc.path, proc)
        # emulate successfully deleted (or deleted in sandboxfs)
        if (sc.ret.err() and exists(hpn)) or sc.ret.ok():
            self.put_deleted_file(hpn)
            self.add_hijack(sc.ret, 0)

    def done(self):
        # XXX.
        print "=" * 60
        for (name, cnt) in self.stat.items():
            mark = "*" if name in SYSCALLS else " "
            print "%s%15s: %3s" % (mark, name, cnt)

        print "-" * 60
        pprint.pprint(self.fds)
        pprint.pprint(self.deleted)
        pprint.pprint(self.cwds)
        # XXX. check
        os.system("tree %s" % self.root)
