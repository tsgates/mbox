import os
import dbg
import pprint

from syscall import *
from util    import *

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

# fd->path converting
FD_ASIS    = 1
FD_SANDBOX = 2
FD_HOST    = 3

class OS:
    def __init__(self, root):
        #
        # cwd    in hostfs
        # dirfd  in sandboxfs
        # filefd in hostfs|sandboxfs
        #
        self.root    = root.rstrip("/")   # root dir of sandboxfs
        self.stat    = defaultdict(int)   # statistics of syscalls
        self.dirents = defaultdict(dict)  # state (seek equivalent)
        self.deleted = defaultdict(set)   # fullpath -> set of filenames
        self.hijack  = defaultdict(list)  # rewriting tasks per process

        # init root
        mkdir(self.root)

    #
    # main driver
    #
    def run(self, proc, sc):
        pid = proc.pid
        if sc.entering:
            assert len(self.hijack[pid]) == 0
            self.stat[sc.name] += 1

        cond = "enter" if sc.entering else "exit"
        func = "%s_%s" % (sc.name, cond)
        if hasattr(self, func):
            dbg.ns(sc)
            getattr(self, func)(proc, sc)

        if sc.entering:
            for (arg, new) in self.hijack[pid]:
                dbg.ns(" -> %s", new)
                arg.hijack(proc, new)
        else:
            for (arg, new) in self.hijack[pid]:
                dbg.ns(" <- %s", arg)
                arg.restore(proc, new)
            # clean them up
            self.hijack[pid] = []

    def add_hijack(self, proc, arg, new):
        self.hijack[proc.pid].append((arg, new))

    def sync_parent_dirs(self, path):
        for crumb in itercrumb(path):
            spn = join(self.root, crumb[1:])
            if dir_exists(crumb) and not dir_exists(spn):
                mkdir(spn)

    def copy_to(self, pn, spn):
        if file_exists(pn):
            dbg.ns(" copy %s -> %s", pn, spn)
            safecopy(pn, spn)

    def getfd(self, proc, fd, form=FD_ASIS):
        path = None
        pn = "/proc/%s/fd/%d" % (proc.pid, fd)
        if exists(pn):
            path = normpath(os.readlink(pn))

        # convert path form
        if form == FD_ASIS:
            return path
        elif form == FD_SANDBOX:
            return self.to_sandboxfs(path)
        elif form == FD_HOST:
            return self.to_hostfs(path)

        # non-exsist fd
        return None

    def getcwd(self, proc):
        cwd = os.readlink("/proc/%s/cwd" % proc.pid)
        assert self.is_hostfs(cwd)
        return cwd

    def chgcwd(self, proc, path):
        dbg.info(" cwd: %s -> %s" % (self.getcwd(proc), path))

    def parse_path(self, path, proc):
        return self.parse_path_dirfd(AT_FDCWD, path, proc)

    def parse_path_dirfd(self, dirfd, path, proc):
        if dirfd == AT_FDCWD:
            cwd = self.getcwd(proc)
        else:
            cwd = self.getfd(proc, dirfd)
        hpn = path.normpath(cwd)
        spn = path.chroot(self.root, self.getcwd(proc))
        return (hpn, spn)

    #
    # handle deleted files
    #
    def is_deleted(self, hpn):
        (d, f) = os.path.split(hpn)
        return f in self.deleted.get(d, [])

    def mark_deleted_file(self, hpn):
        (d, f) = os.path.split(hpn)
        self.deleted[d].add(f)

    def unmark_deleted_file(self, hpn):
        (d, f) = os.path.split(hpn)
        if d in self.deleted and f in self.deleted[d]:
            self.deleted[d].remove(f)

    # a common way to rewrite host -> sandbox path
    def rewrite_path(self, proc, sc, flag = RW_NONE):
        assert hasattr(sc, "path")
        if hasattr(sc, "dirfd"):
            dirfd = sc.dirfd.fd
        else:
            dirfd = AT_FDCWD

        self.__rewrite_path(proc, dirfd, sc.path, flag)

    def __rewrite_path(self, proc, dirfd, path, flag):
        # fetch host/sandbox path name
        (hpn, spn) = self.parse_path_dirfd(dirfd, path, proc)

        # sync up host/sandbox dir hierarchy
        if not exists(spn) and exists(hpn):
            self.sync_parent_dirs(hpn)

        # hijack pathname:
        #  exist in sandbox  : need to use the file in the sandbox
        #  deleted in sandbox: do not look for the path in the host
        #  will be written   : copy the file and use that file path
        if exists(spn) or self.is_deleted(hpn) or flag != RW_NONE:
            # it has writing intent
            if flag == RW_WRITING and not file_exists(spn):
                self.copy_to(hpn, spn)

            # deletion: we know it will fail in syscall(), but it's correct
            # semantic in terms of correctness
            self.add_hijack(proc, path, spn)
        else:
            # use a file in the host: it could be dangerous
            dbg.info(" use: %s" % path)

    #
    # host/sandbox path conversion
    #
    def is_sandboxfs(self, path):
        return normpath(path).startswith(self.root)

    def is_hostfs(self, path):
        return not self.is_sandboxfs(path)

    def to_sandboxfs(self, path):
        pn = normpath(path)
        if self.is_hostfs(pn):
            return chjoin(self.root, pn)
        return pn

    def to_hostfs(self, path):
        pn = normpath(path)
        if self.is_sandboxfs(pn):
            return pn[len(self.root):]
        return pn

    #
    # list of system calls to interleave
    #
    @redirect_at
    def access_enter(self, proc, sc):
        pass

    def faccessat_enter(self, proc, sc):
        self.rewrite_path(proc, sc)

    @redirect_at
    def chmod_enter(self, proc, sc):
        pass

    def fchmodat_enter(self, proc, sc):
        self.rewrite_path(proc, sc, RW_WRITING)

    @redirect_at
    def chown_enter(self, proc, sc):
        pass

    def fchownat_enter(self, proc, sc):
        self.rewrite_path(proc, sc, RW_WRITING)

    def truncate_enter(self, proc, sc):
        self.rewrite_path(proc, sc, RW_WRITING)

    def chdir_exit(self, proc, sc):
        if sc.ret.ok():
            self.chgcwd(proc, sc.path.str)

    def fchdir_enter(self, proc, sc):
        pn = self.getfd(proc, sc.dirfd.fd)
        if pn and self.is_sandboxfs(pn):
            hpn = self.getfd(proc, sc.dirfd.fd, FD_HOST)

            # fd -> path (the first argument)
            path = f_path(hpn, sc)
            path.seq = 0
            self.add_hijack(proc, path, hpn)

            # change the syscall number
            self.add_hijack(proc, f_sysc(0, sc), NR_chdir)

            dbg.info(" fchdir on the sandboxed dirfd: %s" % pn)

    def fchdir_exit(self, proc, sc):
        if sc.ret.ok():
            self.chgcwd(proc, self.getfd(proc, sc.dirfd.fd))

    def getdents_enter(self, proc, sc):
        pass

    def getdents_exit(self, proc, sc):
        pid = proc.pid
        fd  = sc.fd.int

        # exit on current syscall, let's dump hostfs too
        if sc.ret.int == 0:
            state = self.dirents[pid].get(fd, None)
            hpn   = self.getfd(proc, fd, FD_HOST)
            # XXX
            if hpn.startswith("/proc"):
                return
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

            # insert blob
            if len(blob) != 0:
                self.add_hijack(proc, sc.dirp, blob)
                self.dirents[pid][fd] = dirents

            dbg.dirent(" <- #dirent:%s (%s, state:%s, blob:%s)" \
                           % (len(dirents), hpn,
                              state if state is None else len(state),
                              len(blob)))

            # reset state
            if state == [] and len(blob) == 0:
                self.dirents[pid][fd] = None

    def getxattr_enter(self, proc, sc):
        self.rewrite_path(proc, sc)

    def creat_enter(self, proc, sc):
        self.rewrite_path(proc, sc, RW_FORCE)

    @redirect_at
    def open_enter(self, proc, sc):
        pass

    @redirect_at
    def open_exit(self, proc, sc):
        pass

    def openat_enter(self, proc, sc):
        (hpn, spn) = self.parse_path_dirfd(sc.dirfd.fd, sc.path, proc)

        #
        # XXX. if users don't have any permission to modify dirs, we
        #      don't have to sync at all
        # XXX. create a virtual layer to simulate /dev, /sys and /proc
        #
        if hpn.startswith("/dev") or hpn.startswith("/proc"):
            return

        # deleted file/dir
        if self.is_deleted(hpn):
            self.add_hijack(proc, sc.path, spn)
            return

        # for dirs
        if (dir_exists(hpn) and sc.flag.is_dir()) or dir_exists(spn):
            # sync parent dir
            self.sync_parent_dirs(hpn)
            # rewrite pn -> spn
            self.add_hijack(proc, sc.path, spn)
            return

        # for files
        if file_exists(spn):
            # rewrite pn -> spn
            self.add_hijack(proc, sc.path, spn)
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
            self.add_hijack(proc, sc.path, spn)
            return

        # read/write
        if sc.flag.is_wr():
            # sync parent dir
            self.sync_parent_dirs(hpn)
            # copy the file to sandbox
            self.copy_to(hpn, spn)
            # rewrite pn -> spn
            self.add_hijack(proc, sc.path, spn)
            return

    def openat_exit(self, proc, sc):
        # keep tracks of open files
        if not sc.ret.err():
            (hpn, spn) = self.parse_path_dirfd(sc.dirfd.fd, sc.path, proc)
            self.unmark_deleted_file(hpn)

    def rename_enter(self, proc, sc):
        sc.oldfd = at_fd(AT_FDCWD, sc)
        sc.newfd = at_fd(AT_FDCWD, sc)
        self.renameat_enter(proc, sc)

    def rename_exit(self, proc, sc):
        sc.oldfd = at_fd(AT_FDCWD, sc)
        sc.newfd = at_fd(AT_FDCWD, sc)
        self.renameat_exit(proc, sc)

    def renameat_enter(self, proc, sc):
        self.__rewrite_path(proc, sc.oldfd.fd, sc.old, flag=RW_WRITING)
        self.__rewrite_path(proc, sc.newfd.fd, sc.new, flag=RW_FORCE)

    def renameat_exit(self, proc, sc):
        if sc.err.ok():
            (hpn, _) = self.parse_path_dirfd(sc.oldfd.fd, sc.old, proc)
            self.mark_deleted_file(hpn)

    @redirect_at
    def readlink_enter(self, proc, sc):
        pass

    def readlinkat_enter(self, proc, sc):
        self.rewrite_path(proc, sc)

    @redirect_at
    def mkdir_enter(self, proc, sc):
        pass

    def mkdirat_enter(self, proc, sc):
        self.rewrite_path(proc, sc, RW_FORCE)

    def rmdir_enter(self, proc, sc):
        self.rewrite_path(proc, sc, RW_FORCE)

    def rmdir_exit(self, proc, sc):
        (hpn, spn) = self.parse_path(sc.path, proc)
        # emulate successfully deleted (or deleted in sandboxfs)
        if (sc.ret.err() and exists(hpn)) or sc.ret.ok():
            self.mark_deleted_file(hpn)
            self.add_hijack(proc, sc.ret, 0)

    def utimensat_enter(self, proc, sc):
        self.rewrite_path(proc, sc)
            
    @redirect_at
    def stat_enter(self, proc, sc):
        pass

    def fstatat_enter(self, proc, sc):
        self.rewrite_path(proc, sc)

    def newfstatat_enter(self, proc, sc):
        self.fstatat_enter(proc, sc)

    def lstat_enter(self, proc, sc):
        self.stat_enter(proc, sc)

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
            self.mark_deleted_file(hpn)
            self.add_hijack(proc, sc.ret, 0)

    def done(self):
        # XXX.
        print "=" * 60
        for (name, cnt) in self.stat.items():
            mark = "*" if name in SYSCALLS else " "
            print "%s%15s: %3s" % (mark, name, cnt)

        print "-" * 60
        pprint.pprint(self.deleted)
        # XXX. check
        os.system("tree %s" % self.root)
