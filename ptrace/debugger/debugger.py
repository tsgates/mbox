from logging import info, warning, error
from ptrace import PtraceError
from os import waitpid, WNOHANG
from signal import SIGTRAP, SIGSTOP
from errno import ECHILD
from ptrace.debugger import PtraceProcess, ProcessSignal
from ptrace.binding import HAS_PTRACE_EVENTS
if HAS_PTRACE_EVENTS:
    from ptrace.binding.func import (
        PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK,
        PTRACE_O_TRACEEXEC, PTRACE_O_TRACESYSGOOD)

class DebuggerError(PtraceError):
    pass

class PtraceDebugger(object):
    """
    Debugger managing one or multiple processes at the same time.

    Methods
    =======

     * Process list:
       - addProcess(): add a new process
       - deleteProcess(): remove a process from the debugger

     * Wait for an event:
       - waitProcessEvent(): wait for a process event
       - waitSignals(): wait for a signal
       - waitSyscall(): wait for the next syscall event

     * Options:
      - traceForks(): enable fork tracing
      - traceExec(): enable exec() tracing
      - enableSysgood(): enable sysgood option

     * Other:
       - quit(): quit the debugger, terminate all processes

    Operations
    ==========

     - iterarate on all processes: "for process in debugger: ..."
     - get a process by its identifier: "process = debugger[pid]"
     - get the number of processes: len(debugger)

    Attributes
    ==========

     - dict: processes dictionary (pid -> PtraceProcess)
     - list: processes list
     - options: ptrace options
     - trace_fork (bool): fork() tracing is enabled?
     - trace_exec (bool): exec() tracing is enabled?
     - use_sysgood (bool): sysgood option is enabled?
    """
    def __init__(self):
        self.dict = {}   # pid -> PtraceProcess object
        self.list = []
        self.options = 0
        self.trace_fork = False
        self.trace_exec = False
        self.use_sysgood = False
        self.enableSysgood()

    def addProcess(self, pid, is_attached, parent=None):
        """
        Add a new process using its identifier. Use is_attached=False to
        attach an existing (running) process, and is_attached=True to trace
        a new (stopped) process.
        """
        if pid in self.dict:
            raise KeyError("The process %s is already registered!" % pid)
        process = PtraceProcess(self, pid, is_attached, parent=parent)
        info("Attach %s to debugger" % process)
        self.dict[pid] = process
        self.list.append(process)
        try:
            process.waitSignals(SIGTRAP, SIGSTOP)
        except KeyboardInterrupt:
            error(
                "User interrupt! Force the process %s attach "
                "(don't wait for signals)."
                % pid)
        except ProcessSignal, event:
            event.display()
        except:
            process.is_attached = False
            process.detach()
            raise
        if HAS_PTRACE_EVENTS and self.options:
            process.setoptions(self.options)
        return process

    def quit(self):
        """
        Quit the debugger: terminate all processes in reverse order.
        """
        info("Quit debugger")
        # Terminate processes in reverse order
        # to kill children before parents
        processes = list(self.list)
        for process in reversed(processes):
            process.terminate()
            process.detach()

    def _waitpid(self, wanted_pid, blocking=True):
        """
        Wait for a process event from a specific process (if wanted_pid is
        set) or any process (wanted_pid=None). The call is blocking is
        blocking option is True. Return the tuple (pid, status).

        See os.waitpid() documentation for explainations about the result.
        """
        flags = 0
        if not blocking:
            flags |= WNOHANG
        if wanted_pid:
            if wanted_pid not in self.dict:
                raise DebuggerError("Unknown PID: %r" % wanted_pid, pid=wanted_pid)

            pid, status = waitpid(wanted_pid, flags)
        else:
            pid, status = waitpid(-1, flags)
        if (blocking or pid) and wanted_pid and (pid != wanted_pid):
            raise DebuggerError("Unwanted PID: %r (instead of %s)"
                % (pid, wanted_pid), pid=pid)
        return pid, status

    def _wait(self, wanted_pid, blocking=True):
        """
        Wait for a process event from the specified process identifier. If
        blocking=False, return None if there is no new event, otherwise return
        an objet based on ProcessEvent.
        """
        process = None
        while not process:
            try:
                pid, status = self._waitpid(wanted_pid, blocking)
            except OSError, err:
                if err.errno == ECHILD:
                    process = self.dict[wanted_pid]
                    return process.processTerminated()
                else:
                    raise err
            if not blocking and not pid:
                return None
            try:
                process = self.dict[pid]
            except KeyError:
                warning("waitpid() warning: Unknown PID %r" % pid)
        return process.processStatus(status)

    def waitProcessEvent(self, pid=None, blocking=True):
        """
        Wait for a process event from a specific process (if pid option is
        set) or any process (default). If blocking=False, return None if there
        is no new event, otherwise return an objet based on ProcessEvent.
        """
        return self._wait(pid, blocking)

    def waitSignals(self, *signals, **kw):
        """
        Wait for any signal or some specific signals (if specified) from a
        specific process (if pid keyword is set) or any process (default).
        Return a ProcessSignal object or raise an unexpected ProcessEvent.
        """
        pid = kw.get('pid', None)
        while True:
            event = self._wait(pid)
            if event.__class__ != ProcessSignal:
                raise event
            signum = event.signum
            if signum in signals or not signals:
                return event
            raise event

    def waitSyscall(self, process=None):
        """
        Wait for the next syscall event (enter or exit) for a specific process
        (if specified) or any process (default). Return a ProcessSignal object
        or raise an unexpected ProcessEvent.
        """
        signum = SIGTRAP
        if self.use_sysgood:
            signum |= 0x80
        if process:
            return self.waitSignals(signum, pid=process.pid)
        else:
            return self.waitSignals(signum)

    def deleteProcess(self, process=None, pid=None):
        """
        Delete a process from the process list.
        """
        if not process:
            try:
                process = self.dict[pid]
            except KeyError:
                return
        try:
            del self.dict[process.pid]
        except KeyError:
            pass
        try:
            self.list.remove(process)
        except ValueError:
            pass

    def traceFork(self):
        """
        Enable fork() tracing. Do nothing if it's not supported.
        """
        if not HAS_PTRACE_EVENTS:
            raise DebuggerError("Tracing fork events is not supported on this architecture or operating system")
        self.options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
        self.trace_fork = True
        info("Debugger trace forks (options=%s)" % self.options)

    def traceExec(self):
        """
        Enable exec() tracing. Do nothing if it's not supported.
        """
        if not HAS_PTRACE_EVENTS:
            # no effect on OS without ptrace events
            return
        self.trace_exec = True
        self.options |= PTRACE_O_TRACEEXEC

    def enableSysgood(self):
        """
        Enable sysgood option: ask the kernel to set bit #7 of the signal
        number if the signal comes from the kernel space. If the signal comes
        from the user space, the bit is unset.
        """
        if not HAS_PTRACE_EVENTS:
            # no effect on OS without ptrace events
            return
        self.use_sysgood = True
        self.options |= PTRACE_O_TRACESYSGOOD

    def __getitem__(self, pid):
        return self.dict[pid]

    def __iter__(self):
        return iter(self.list)

    def __len__(self):
        return len(self.list)

