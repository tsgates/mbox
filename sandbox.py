#!/usr/bin/env python2

import os
import re
import dbg
import pprint
import chore

from sys      import stderr, exit
from optparse import OptionParser
from ptrace   import PtraceError

from ptrace.debugger import *
from ptrace.syscall  import *

from ptrace.error        import PTRACE_ERRORS
from ptrace.error        import writeError
from ptrace.func_call    import FunctionCallOptions
from ptrace.ctypes_tools import formatAddress

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
        self.deleted = defaultdict(set)   # path -> set of filenames

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
        return self.cwds.get(proc.pid, self.cwd)

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
        npn = path.normpath(cwd)
        spn = path.chroot(self.root, self.getcwd(proc))
        return (npn, spn)

    #
    # list of system calls to interleave
    #
    @redirect_at
    def access_enter(self, proc, sc):
        pass

    def faccessat_enter(self, proc, sc):
        (npn, spn) = self.parse_path_dirfd(sc.dirfd.fd, sc.path, proc)
        if exists(spn):
            self.add_hijack(sc.path, spn)

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
            npn   = self.fds[pid][fd]
            sdir  = os.listdir(chjoin(self.root, npn))

            # fetch previous dirents
            if state is None:
                # initial to dump hostfs
                dirents = get_dirents(npn)
            else:
                dirents = state

            # dump dirents
            blob = ""
            while len(dirents) > 0:
                d = dirents.pop()
                if d.d_name in sdir:
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
        (npn, spn) = self.parse_path(sc.path, proc)
        if exists(spn):
            self.add_hijack(sc.path, spn)

    @redirect_at
    def open_enter(self, proc, sc):
        pass

    def open_exit(self, proc, sc):
        self.openat_exit(proc, sc)

    def openat_enter(self, proc, sc):
        (npn, spn) = self.parse_path_dirfd(sc.dirfd.fd, sc.path, proc)

        #
        # XXX. create a virtual layer to simulate /dev, /sys and /proc
        #

        # for dirs
        if (dir_exists(npn) and sc.flag.is_dir()) or dir_exists(spn):
            # sync parent dir
            self.sync_parent_dirs(npn)
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
            self.sync_parent_dirs(npn)
            # rewrite pn -> spn
            self.add_hijack(sc.path, spn)
            return

        # read/write
        if sc.flag.is_wr():
            # sync parent dir
            self.sync_parent_dirs(npn)
            # copy the file to sandbox
            self.copy_to(npn, spn)
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
        (npn, spn) = self.parse_path_dirfd(sc.dirfd.fd, sc.path, proc)
        # sync & overwrite if exists in sandboxfs
        if exists(spn):
            self.sync_parent_dirs(npn)
            self.add_hijack(sc.path, spn)

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
        (npn, spn) = self.parse_path_dirfd(sc.dirfd.fd, sc.path, proc)
        self.sync_parent_dirs(npn)
        self.add_hijack(sc.path, spn)

    def unlinkat_exit(self, proc, sc):
        (npn, spn) = self.parse_path_dirfd(sc.dirfd.fd, sc.path, proc)
        # emulate successfully deleted (or deleted in sandboxfs)
        if (sc.ret.err() and exists(npn)) or sc.ret.ok():
            (d, f) = os.path.split(spn)
            self.deleted[d].add(f)
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

# interactively committing modified files to the host
def interactive(box):
    class ask_diff:
        desc = "d:diff"
        def __call__(self, spn, hpn):
            os.system("diff -urN '%s' '%s'" % (hpn, spn))

    class ask_view:
        desc = "v:view"
        def __call__(self, spn, hpn):
            os.system("cat '%s'" % (spn))

    class ask_ignore:
        desc = "i:ignore"
        def __call__(self, spn, hpn):
            return True

    class ask_commit:
        desc = "c:commit"
        def __call__(self, spn, hpn):
            return True

    class ask_quit:
        desc = "q:quit"
        def __call__(self, spn, hpn):
            exit(0)

    menu = [ask_diff(), ask_view(), ask_ignore(), ask_commit(), ask_quit()]
    for root, dirs, files in os.walk(box.root):
        for name in files:
            spn = join(root, name)
            hpn = spn.lstrip(box.root.rstrip("/"))

            stop = False
            while not stop:
                print "> %s" % spn
                print "  [?]" + ", ".join(m.desc for m in menu) + "> ",
                c = kbhit()
                print ""
                for m in menu:
                    if m.desc.startswith(c+":"):
                        stop = m(spn, hpn)

class Sandbox:
    def __init__(self, opts, args):
        self.opts = opts
        self.args = args

    def run(self):
        self.debugger = PtraceDebugger()
        try:
            self.run_debugger()
        except ProcessExit, event:
            self.event_exit(event)
        except PtraceError, err:
            dbg.fatal("ptrace() error: %s" % err)
        except KeyboardInterrupt:
            dbg.error("Interrupted.")
        self.debugger.quit()
        self.os.done()

        # add a flag not to be interactive
        if self.opts.interactive:
            chore.interactive(self.os)

    def print_syscall(self, syscall):
        name = syscall.name
        text = syscall.format()

        if syscall.result is not None:
            text = "%-40s = %s" % (text, syscall.result_text)

        prefix = []
        prefix.append("[%s]" % syscall.process.pid)
        prefix.append(">" if syscall.is_enter() else "<")

        dbg.info(''.join(prefix) + ' ' + text)

    def loop(self, proc):
        # first query to break at next syscall
        proc.syscall()

        # loop until no process
        while self.debugger:
            # wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
                proc = event.process
            except ProcessExit, event:
                self.event_exit(event)
                continue
            except ProcessSignal, event:
                proc.syscall(event.signum)
                continue
            except NewProcessEvent, event:
                self.event_new_proc(event)
                continue
            except ProcessExecution, event:
                self.event_proc_exec(event)
                continue

            # process syscall enter or exit
            self.handle_syscall(proc)

    def handle_syscall(self, proc):
        syscall = proc.getSyscall(self.syscall_options)

        # print out system calls
        if self.opts.strace and syscall:
            self.print_syscall(syscall)

        # emulate os
        if not self.opts.no_sandbox:
            self.os.run(proc, syscall)

        # break at next syscall
        proc.syscall()

    def event_exit(self, event):
        # display syscall which has not exited
        state = event.process.syscall_state
        if (state.next_event == "exit") \
          and (not True) \
          and state.syscall:
            self.print_syscall(state.syscall)

        # display exit message
        dbg.trace("*** %s ***" % event)

    def event_new_proc(self, event):
        process = event.process
        dbg.trace("*** New process %s ***" % process.pid)
        process.syscall()
        process.parent.syscall()

    def event_proc_exec(self, event):
        process = event.process
        dbg.trace("*** Process %s execution ***" % process.pid)
        process.syscall()

    def run_proc(self, args):
        pid = self.fork(args)
        try:
            proc = self.debugger.addProcess(pid, is_attached=True)
        except PtraceError as e:
            if e.errno == EPERM:
                fatal("No permission: %s" % str(e))
            fatal("Can't be attached: pid=%s" % pid)
        except ChildError as e:
            fatal("Can't be attached: %s" % str(e))
        return (pid, proc)

    def run_debugger(self):
        # set ptrace flags
        try:
            self.debugger.traceFork()
            self.debugger.traceExec()
            self.debugger.enableSysgood()
        except DebuggerError:
            dbg.fatal("OS doesn't support to trace fork(), exec()")

        (pid, proc) = self.run_proc(self.args)

        # for strace format
        self.syscall_options = FunctionCallOptions(
            write_types=False,
            write_argname=False,
            string_max_length=60,
            replace_socketcall=False,
            write_address=False,
            max_array_count=300,
        )
        self.syscall_options.instr_pointer = False

        # init os instance
        self.os = OS(self.parse_root(self.opts.root, pid), os.getcwd())
        self.loop(proc)

    def fork(self, args, env=None):
        argv = [which(args[0])] + args[1:]
        return createChild(argv, False, env)

    def parse_root(self, path, pid):
        return path.replace("%PID", str(pid))

def print_syscalls(opts):
    pn = "syscall64.tbl"
    if not exists(pn):
        dbg.fatal("Failed to find %s" % pn)

    for l in open(pn):
        l = l.strip()
        if l.startswith("#") or len(l) == 0:
            continue

        # parsing syscall table
        toks = l.split()
        (num, abi, name) = toks[:3]
        entry = "N/A" if len(toks) < 4 else toks[3]

        # what we are keeping track of
        mark = "*" if name in SYSCALLS else " "
        print "%s% 3s: %s" % (mark, num, name)

def parse_args():
    parser = OptionParser(usage="%prog [options] -- program [arg1 arg2 ...]")
    parser.add_option("--list-syscalls", "-l",
                      help="Display system calls and exit",
                      action="store_true", default=None)
    parser.add_option("--strace", "-s",
                      help="Print out system calls",
                      action="store_true", default=False)
    parser.add_option("--no-sandbox", "-n",
                      help="No sandboxing",
                      action="store_true", default=False)
    parser.add_option("-r", "--root",
                      help="Root of the sandbox dir (ex /tmp/sandbox-%PID)",
                      default="/tmp/sandbox-%PID")
    parser.add_option("-q", "--quiet",
                      help="Quiet",
                      action="store_true", default=False)
    parser.add_option("-i", "--interact",
                      help="Interactivly checking modified files",
                      action="store_true", default=False)
    (opts, args) = parser.parse_args()

    # checking sanity
    if len(args) == 0 and not opts.list_syscalls:
        parser.print_help()
        exit(1)

    # control verbosity
    if opts.quiet:
        dbg.quiet(dbg, ["error"])

    return (opts, args)

if __name__ == "__main__":
    (opts, args) = parse_args()

    if opts.list_syscalls:
        print_syscalls(opts)
        exit(1)

    Sandbox(opts, args).run()