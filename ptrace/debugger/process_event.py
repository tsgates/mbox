from ptrace.signames import signalName

class ProcessEvent(Exception):
    """
    A process event: program exit, program killed by a signal, program
    received a signal, etc.

    The attribute "process" contains the related process.
    """
    def __init__(self, process, message):
        Exception.__init__(self, message)
        self.process = process

class ProcessExit(ProcessEvent):
    """
    Process exit event:
     - process kill by a signal (if signum attribute is not None)
     - process exited with a code (if exitcode attribute is not None)
     - process terminated abnormally (otherwise)
    """
    def __init__(self, process, signum=None, exitcode=None):
        pid = process.pid
        if signum:
            message = "Process %s killed by signal %s" % (
                pid, signalName(signum))
        elif exitcode is not None:
            if not exitcode:
                message = "Process %s exited normally" % pid
            else:
                message = "Process %s exited with code %s" % (pid, exitcode)
        else:
            message = "Process %s terminated abnormally" % pid
        ProcessEvent.__init__(self, process, message)
        self.signum = signum
        self.exitcode = exitcode

class ProcessExecution(ProcessEvent):
    """
    Process execution: event send just after the process calls the exec()
    syscall if exec() tracing option is enabled.
    """
    def __init__(self, process):
        ProcessEvent.__init__(self, process, "Process %s execution" % process.pid)

class NewProcessEvent(ProcessEvent):
    """
    New process: event send when a process calls the fork() syscall if fork()
    tracing option is enabled. The attribute process contains the new child
    process.
    """
    def __init__(self, process):
        ProcessEvent.__init__(self, process, "New process %s" % process.pid)

