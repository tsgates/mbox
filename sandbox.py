#!/usr/bin/env python2

import os
import re
import dbg
import pprint

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
    def chdir_enter(self, proc, sc):
        pass

    def chdir_exit(self, proc, sc):
        # XXX. update self.cwd[pid]
        pass

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

    def open_enter(self, proc, sc):
        sc.dirfd = at_fd(AT_FDCWD, sc)
        self.openat_enter(proc, sc)

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

    def stat_enter(self, proc, sc):
        (npn, spn) = self.parse_path(sc.path, proc)
        # sync & overwrite if exists in sandboxfs
        if exists(spn):
            self.sync_parent_dirs(npn)
            self.add_hijack(sc.path, spn)

    def fstat_enter(self, proc, sc):
        pass

    def fstat_exit(self, proc, sc):
        pass

    def lstat_enter(self, proc, sc):
        self.stat_enter(proc, sc)

    def lstat_exit(self, proc, sc):
        pass

    def unlink_enter(self, proc, sc):
        sc.dirfd = at_fd(AT_FDCWD, sc)
        self.unlinkat_enter(self, proc, sc)

    def unlink_exit(self, proc, sc):
        sc.dirfd = at_fd(AT_FDCWD, sc)
        self.unlinkat_exit(self, proc, sc)

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
        for (n, v) in self.stat.items():
            print "%15s: %3s" % (n, v)
        pprint.pprint(self.fds)
        pprint.pprint(self.deleted)
        # XXX. check
        os.system("tree %s" % self.root)

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
        return createChild(args, False, env)

    def parse_root(self, path, pid):
        return path.replace("%PID", str(pid))

def print_syscalls():
    syscalls = SYSCALL_NAMES.items()
    syscalls.sort(key=lambda data: data[0])
    for num, name in syscalls:
        print "% 3s: %s" % (num, name)

def parse_args():
    parser = OptionParser(usage="%prog [options] -- program [arg1 arg2 ...]")
    parser.add_option("--list-syscalls",
                      help="Display system calls and exit",
                      action="store_true", default=False)
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
    (opts, args) = parser.parse_args()

    # checking sanity
    if len(args) == 0:
        parser.print_help()
        exit(1)

    # control verbosity
    if opts.quiet:
        dbg.quiet(dbg, ["error"])

    return (opts, args)

if __name__ == "__main__":
    (opts, args) = parse_args()

    if opts.list_syscalls:
        print_syscalls()
        exit(1)

    Sandbox(opts, args).run()